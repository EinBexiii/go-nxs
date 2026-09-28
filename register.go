package nxs

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"
)

// unsigned performs an enrollment operation, which is not signed with the machine key.
func (p *Provider) unsigned(ctx context.Context, op string, body any, bearer string, v any) error {
	b, err := marshal(body)
	if err != nil {
		return err
	}
	return p.client.do(ctx, request{method: http.MethodPost, url: p.disc.Operations[op], body: b, bearer: bearer}, v)
}

// register obtains a registration, recovering the saved one if present.
func (p *Provider) register(ctx context.Context) error {
	thumbprint := publicJWK(&p.key.PublicKey).thumbprint()
	if p.st.Registration != nil {
		return p.recover(ctx, p.st.Registration.RegistrationID, thumbprint)
	}
	if c := p.st.Challenge; c != nil {
		// The completion of this challenge may have been lost.
		if p.recover(ctx, c.ChallengeID, thumbprint) == nil {
			return nil
		}
		if time.Now().UnixMilli() < c.ExpiresAt {
			return p.enroll(ctx, c, thumbprint)
		}
		p.st.Challenge = nil
	}
	return p.enroll(ctx, nil, thumbprint)
}

func (p *Provider) enroll(ctx context.Context, c *challenge, thumbprint string) error {
	bearer := p.conf.Token != ""
	if c == nil {
		scheme := schemeAnonymous
		if bearer {
			scheme = schemeBearer
		}
		pub := publicJWK(&p.key.PublicKey)
		c = &challenge{}
		if err := p.unsigned(ctx, "register", registerRequest{
			Protocol:      Protocol,
			Mode:          p.conf.Mode,
			Profile:       Profile,
			PublicKeyJWK:  &pub,
			Label:         p.conf.Label,
			Authorization: &authorization{Scheme: scheme},
			Placement:     p.conf.Placement,
		}, p.conf.Token, c); err != nil {
			return fmt.Errorf("nxs: register: %w", err)
		}
		p.st.Challenge = c
		if err := p.store.save(p.st); err != nil {
			return err
		}
	}
	if err := p.checkChallenge(c, thumbprint, bearer); err != nil {
		return err
	}

	idempotencyKey := randomID()
	nonce, err := c.solve(idempotencyKey, func() bool { return time.Now().UnixMilli() >= c.ExpiresAt })
	if err != nil {
		return err
	}
	reg, err := p.complete(ctx, c, p.key, nonce, idempotencyKey)
	if err != nil {
		return err
	}
	if err := p.checkPlacement(reg); err != nil {
		return err
	}
	p.st.TicketKeys = nil
	if reg.TicketKey != nil {
		p.st.TicketKeys = []ticketKey{*reg.TicketKey}
		reg.TicketKey = nil
	}
	p.st.Registration, p.st.Challenge = reg, nil
	return p.store.save(p.st)
}

// checkChallenge checks that an enrollment challenge matches the configuration.
func (p *Provider) checkChallenge(c *challenge, thumbprint string, bearer bool) error {
	if err := c.validate(p.origin, thumbprint); err != nil {
		return err
	}
	switch mode := c.Context.Mode; {
	case p.conf.Mode == ModeAutomatic && (mode == ModeNewService || (bearer && mode == ModeAttachInstance)):
	case p.conf.Mode != ModeAutomatic && mode == p.conf.Mode:
	default:
		return fmt.Errorf("nxs: challenge selected unexpected mode %q", mode)
	}
	var region, pool, tags string
	if pl := p.conf.Placement; pl != nil {
		region, pool = pl.Region, pl.Pool
		var err error
		if tags, err = tagsDigest(pl.Tags); err != nil {
			return err
		}
	}
	if c.Context.Region != region || c.Context.Pool != pool || c.Context.TagsDigest != tags {
		return errors.New("nxs: challenge placement changed")
	}
	if bearer && (c.Authorization == nil || c.Authorization.Scheme != schemeBearer || c.Authorization.Reference == "" || c.Pow.Difficulty != 0) {
		return errors.New("nxs: challenge does not reflect bearer authorization")
	}
	return nil
}

func (p *Provider) checkPlacement(reg *registration) error {
	var want Placement
	if p.conf.Placement != nil {
		want = *p.conf.Placement
	}
	if reg.Placement.Region != want.Region || reg.Placement.Pool != want.Pool || !maps.Equal(reg.Placement.Tags, want.Tags) {
		return errors.New("nxs: registration placement changed")
	}
	return nil
}

// recover proves ownership of the machine key to resume a registration in a new generation.
func (p *Provider) recover(ctx context.Context, registrationID, thumbprint string) error {
	c := &challenge{}
	if err := p.unsigned(ctx, "register", registerRequest{Protocol: Protocol, Profile: Profile, RegistrationID: registrationID}, "", c); err != nil {
		return fmt.Errorf("nxs: recover: %w", err)
	}
	// A rotation may have been interrupted after the provider installed the pending key.
	key, pending := p.key, false
	if p.st.PendingPrivateKey != "" {
		if k, err := decodePrivateKey(p.st.PendingPrivateKey); err == nil && publicJWK(&k.PublicKey).thumbprint() == c.Thumbprint {
			key, thumbprint, pending = k, c.Thumbprint, true
		}
	}
	if err := c.validate(p.origin, thumbprint); err != nil {
		return err
	}
	if c.Context.Mode != modeRecover || c.Context.RegistrationID != registrationID || c.Pow.Difficulty != 0 || c.ExpiresAt <= time.Now().UnixMilli() {
		return errors.New("nxs: unbound recovery challenge")
	}
	reg, err := p.complete(ctx, c, key, "0", randomID())
	if err != nil {
		return err
	}
	if reg.RegistrationID != registrationID || (p.st.Registration != nil && reg.InstanceID != p.st.Registration.InstanceID) {
		return errors.New("nxs: recovered registration identity changed")
	}
	// One-time secrets are only accepted from a fresh enrollment.
	reg.TicketKey = nil
	p.st.Registration, p.st.Challenge = reg, nil
	if pending {
		p.st.PrivateKey, p.st.PendingPrivateKey, p.key = p.st.PendingPrivateKey, "", key
	}
	return p.store.save(p.st)
}

func (p *Provider) complete(ctx context.Context, c *challenge, key *ecdsa.PrivateKey, nonce, idempotencyKey string) (*registration, error) {
	proof, err := c.proof(nonce, idempotencyKey)
	if err != nil {
		return nil, err
	}
	sig, err := sign(key, proof)
	if err != nil {
		return nil, err
	}
	reg := &registration{}
	if err := p.unsigned(ctx, "complete", completeRequest{
		Protocol:       Protocol,
		ChallengeID:    c.ChallengeID,
		ProofNonce:     nonce,
		IdempotencyKey: idempotencyKey,
		Signature:      sig,
	}, "", reg); err != nil {
		return nil, fmt.Errorf("nxs: complete: %w", err)
	}
	if err := reg.validate(p.origin); err != nil {
		return nil, err
	}
	return reg, nil
}

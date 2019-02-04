/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	cloudDNSServiceAccountKey = "service-account.json"
)

type solver interface {
	Present(domain, fqdn, value string) error
	CleanUp(domain, fqdn, value string) error
}

// Solver is a solver for the acme dns01 challenge.
// Given a Certificate object, it determines the correct DNS provider based on
// the certificate, and configures it based on the referenced issuer.
type Solver struct {
	*controller.Context
	secretLister corev1listers.SecretLister
	providers    *Registry
}

// Present performs the work to configure DNS to resolve a DNS01 challenge.
func (s *Solver) Present(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	slv, providerConfig, err := s.solverForChallenge(issuer, ch)
	if err != nil {
		return err
	}

	fqdn, value, _, err := util.DNS01Record(ch.Spec.DNSName, ch.Spec.Key, s.DNS01Nameservers, followCNAME(providerConfig.CNAMEStrategy))
	if err != nil {
		return err
	}

	glog.Infof("Presenting DNS01 challenge for domain %q", ch.Spec.DNSName)
	return slv.Present(ch.Spec.DNSName, fqdn, value)
}

// Check verifies that the DNS records for the ACME challenge have propagated.
func (s *Solver) Check(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {

	fqdn, value, ttl, err := util.DNS01Record(ch.Spec.DNSName, ch.Spec.Key, s.DNS01Nameservers, false)
	if err != nil {
		return err
	}

	glog.Infof("Checking DNS propagation for %q using name servers: %v", ch.Spec.DNSName, s.Context.DNS01Nameservers)

	ok, err := util.PreCheckDNS(fqdn, value, s.Context.DNS01Nameservers,
		s.Context.DNS01CheckAuthoritative)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("DNS record for %q not yet propagated", ch.Spec.DNSName)
	}

	glog.Infof("Waiting DNS record TTL (%ds) to allow propagation of DNS record for domain %q", ttl, fqdn)
	time.Sleep(time.Second * time.Duration(ttl))
	glog.Infof("ACME DNS01 validation record propagated for %q", fqdn)

	return nil
}

// CleanUp removes DNS records which are no longer needed after
// certificate issuance.
func (s *Solver) CleanUp(ctx context.Context, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) error {
	if ch.Spec.Config.DNS01 == nil {
		return fmt.Errorf("challenge dns config must be specified")
	}

	slv, providerConfig, err := s.solverForChallenge(issuer, ch)
	if err != nil {
		return err
	}

	fqdn, value, _, err := util.DNS01Record(ch.Spec.DNSName, ch.Spec.Key, s.DNS01Nameservers, followCNAME(providerConfig.CNAMEStrategy))
	if err != nil {
		return err
	}

	return slv.CleanUp(ch.Spec.DNSName, fqdn, value)
}

func followCNAME(strategy v1alpha1.CNAMEStrategy) bool {
	if strategy == v1alpha1.FollowStrategy {
		return true
	}
	return false
}

// solverForChallenge returns a Solver for the given providerName.
// The providerName is the name of an ACME DNS-01 challenge provider as
// specified on the Issuer resource for the Solver.
func (s *Solver) solverForChallenge(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (solver, *v1alpha1.ACMEIssuerDNS01Provider, error) {
	resourceNamespace := s.ResourceNamespace(issuer)

	providerName := ch.Spec.Config.DNS01.Provider
	if providerName == "" {
		return nil, nil, fmt.Errorf("dns01 challenge provider name must be set")
	}

	providerConfig, err := issuer.GetSpec().ACME.DNS01.Provider(providerName)
	if err != nil {
		return nil, nil, err
	}

	var impl solver
	var kind string
	var config interface{}
	switch {
	case providerConfig.Akamai != nil:
		kind="akamai"
		config=providerConfig.Akamai

	case providerConfig.CloudDNS != nil:
		kind="clouddns"
		config=providerConfig.CloudDNS

	case providerConfig.Cloudflare != nil:
		kind="cloudflare"
		config=providerConfig.Cloudflare

	case providerConfig.DigitalOcean != nil:
		kind="digitalocean"
		config=providerConfig.DigitalOcean

	case providerConfig.Route53 != nil:
		kind="route53"
		config=providerConfig.Route53

	case providerConfig.AzureDNS != nil:
		kind="azuredns"
		config=providerConfig.AzureDNS

	case providerConfig.AcmeDNS != nil:
		kind="acmedns"
		config=providerConfig.AcmeDNS

	case providerConfig.RFC2136 != nil:
		kind="rfc2136"
		config=providerConfig.RFC2136

	default:
		if providerConfig.Kind!=nil && *providerConfig.Kind!="" {
			kind=*providerConfig.Kind
			config=providerConfig.ProviderConfig
		} else {
			return nil, nil, fmt.Errorf("no dns provider config specified for provider %q", providerName)
		}
	}

	factory:=s.providers.Get(kind)
	if factory==nil {
		return nil, nil, fmt.Errorf("unknown provider kind %q configured for provider %q", kind, providerName)
	}
	impl, err = factory.Create(s,issuer,ch, resourceNamespace, config)

	if err != nil {
	    return nil, nil, err
	}
	return impl, providerConfig, nil
}

// NewSolver creates a Solver which can instantiate the appropriate DNS
// provider.
func NewSolver(ctx *controller.Context) *Solver {
	return &Solver{
		ctx,
		ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		DefaultRegistry,
	}
}

func (s *Solver) Secret(namespace, name string) (*corev1.Secret, error) {
	return s.secretLister.Secrets(namespace).Get(name)
}

func (s *Solver) LoadSecretData(selector *v1alpha1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := s.secretLister.Secrets(ns).Get(selector.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

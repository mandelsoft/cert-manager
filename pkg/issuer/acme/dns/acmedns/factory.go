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

package acmedns

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	val "github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/util"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"reflect"
)


func init() {
	dns.DefaultRegistry.Register("acmedns", NewFactory(nil))
}

type Constructor func (host string, accountJson []byte, dns01Nameservers []string) (*DNSProvider, error)

type Factory struct {
	constructor Constructor
}

func NewFactory(constructor Constructor) dns.ProviderFactory {
	if constructor==nil {
		constructor=NewDNSProviderHostBytes
	}
	return &Factory{constructor}
}

func (f *Factory) ResolverType() reflect.Type {
	return reflect.TypeOf(&DNSProvider{})
}

func (f *Factory) Validate(rawconfig interface{}, fldPath *field.Path)  field.ErrorList{
	var config v1alpha1.ACMEIssuerDNS01ProviderAcmeDNS
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		el = append(el, val.ValidateSecretKeySelector(&config.AccountSecret, fldPath.Child("accountSecretRef"))...)
		if len(config.Host) == 0 {
			el = append(el, field.Required(fldPath.Child( "host"), ""))
		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderAcmeDNS

	err:= util.GetConfig(rawconfig,&config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling acmedns config")
	}

	accountSecret, err := s.Secret(resourceNamespace,config.AccountSecret.Name)
	if err != nil {
		return nil, fmt.Errorf("error getting acmedns accounts secret: %s", err)
	}

	accountSecretBytes, ok := accountSecret.Data[config.AccountSecret.Key]
	if !ok {
		return nil, fmt.Errorf("error getting acmedns accounts secret: key '%s' not found in secret", config.AccountSecret.Key)
	}

	impl, err := f.constructor(
		config.Host,
		accountSecretBytes,
		s.DNS01Nameservers,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating acmedns challenge solver: %s", err)
	}

	return impl, nil
}



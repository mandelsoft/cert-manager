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

package rfc2136

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	val "github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/util"
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"strings"
)


func init() {
	dns.DefaultRegistry.Register("rfc2136", NewFactory(nil))
}

type Constructor func (nameserver, tsigAlgorithm, tsigKeyName, tsigSecret string, dns01Nameservers []string) (*DNSProvider, error)

type Factory struct {
	constructor Constructor
}

func NewFactory(constructor Constructor) dns.ProviderFactory {
	if constructor==nil {
		constructor=NewDNSProviderCredentials
	}
	return &Factory{constructor}
}

func (f *Factory) ResolverType() reflect.Type {
	return reflect.TypeOf(&DNSProvider{})
}

func (f *Factory) Validate(rawconfig interface{}, fldPath *field.Path)  field.ErrorList{
	var config v1alpha1.ACMEIssuerDNS01ProviderRFC2136
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		// Nameserver is the only required field for RFC2136
		if len(config.Nameserver) == 0 {
			el = append(el, field.Required(fldPath.Child("nameserver"), ""))
		} else {
			if _, err := ValidNameserver(config.Nameserver); err != nil {
				el = append(el, field.Invalid(fldPath.Child("nameserver"), "", "Nameserver invalid. Check the documentation for details."))
			}
		}
		if len(config.TSIGAlgorithm) > 0 {
			present := false
			for _, b := range GetSupportedAlgorithms() {
				if b == strings.ToUpper(config.TSIGAlgorithm) {
					present = true
				}
			}
			if !present {
				el = append(el, field.NotSupported(fldPath.Child("tsigAlgorithm"), "", GetSupportedAlgorithms()))
			}
		}
		if len(config.TSIGKeyName) > 0 {
			el = append(el, val.ValidateSecretKeySelector(&config.TSIGSecret, fldPath.Child( "tsigSecretSecretRef"))...)
		}

		if len(val.ValidateSecretKeySelector(&config.TSIGSecret, fldPath.Child("tsigSecretSecretRef"))) == 0 {
			if len(config.TSIGKeyName) <= 0 {
				el = append(el, field.Required(fldPath.Child( "tsigKeyName"), ""))
			}

		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderRFC2136

	err:=util.GetConfig(rawconfig,&config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling rfc2136 config")
	}

	var secret string
	if len(config.TSIGSecret.Name) > 0 {
		tsigSecret, err := s.Secret(resourceNamespace,config.TSIGSecret.Name)
		if err != nil {
			return nil,  fmt.Errorf("error getting rfc2136 service account: %s", err.Error())
		}
		secretBytes, ok := tsigSecret.Data[config.TSIGSecret.Key]
		if !ok {
			return nil, fmt.Errorf("error getting rfc2136 secret key: key '%s' not found in secret", config.TSIGSecret.Key)
		}
		secret = string(secretBytes)
	}

	impl, err := f.constructor(
		config.Nameserver,
		string(config.TSIGAlgorithm),
		config.TSIGKeyName,
		secret,
		s.DNS01Nameservers,
	)
	if err != nil {
		return nil,  fmt.Errorf("error instantiating rfc2136 challenge solver: %s", err.Error())
	}

	return impl, nil
}


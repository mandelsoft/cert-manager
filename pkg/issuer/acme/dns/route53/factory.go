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

package route53

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"reflect"
	"strings"
)


func init() {
	dns.DefaultRegistry.Register("route53", NewFactory(nil))
}

type Constructor func (accessKeyID, secretAccessKey, hostedZoneID, region string, ambient bool, dns01Nameservers []string) (*DNSProvider, error)

type Factory struct {
	constructor Constructor
}

func NewFactory(constructor Constructor) dns.ProviderFactory {
	if constructor==nil {
		constructor=NewDNSProvider
	}
	return &Factory{constructor}
}

func (f *Factory) ResolverType() reflect.Type {
	return reflect.TypeOf(&DNSProvider{})
}

func (f *Factory) Validate(rawconfig interface{}, fldPath *field.Path)  field.ErrorList{
	var config v1alpha1.ACMEIssuerDNS01ProviderRoute53
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		// region is the only required field for route53 as ambient credentials can be used instead
		if len(config.Region) == 0 {
			el = append(el, field.Required(fldPath.Child( "region"), ""))
		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderRoute53

	err:=util.GetConfig(rawconfig,&config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling route53 config")
	}

	secretAccessKey := ""
	if config.SecretAccessKey.Name != "" {
		secretAccessKeySecret, err := s.Secret(resourceNamespace,config.SecretAccessKey.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting route53 secret access key: %s", err)
		}

		secretAccessKeyBytes, ok := secretAccessKeySecret.Data[config.SecretAccessKey.Key]
		if !ok {
			return nil, fmt.Errorf("error getting route53 secret access key: key '%s' not found in secret", config.SecretAccessKey.Key)
		}
		secretAccessKey = string(secretAccessKeyBytes)
	}

	impl, err := f.constructor(
		strings.TrimSpace(config.AccessKeyID),
		strings.TrimSpace(secretAccessKey),
		config.HostedZoneID,
		config.Region,
		s.CanUseAmbientCredentials(issuer),
		s.DNS01Nameservers,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
	}

	return impl, nil
}


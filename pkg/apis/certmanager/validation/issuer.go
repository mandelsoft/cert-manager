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

package validation

import (
	"crypto/x509"
	"fmt"
	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Validation functions for cert-manager v1alpha1 Issuer types

func ValidateIssuer(iss *v1alpha1.Issuer) field.ErrorList {
	allErrs := ValidateIssuerSpec(&iss.Spec, field.NewPath("spec"))
	return allErrs
}

func ValidateIssuerSpec(iss *v1alpha1.IssuerSpec, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	el = ValidateIssuerConfig(&iss.IssuerConfig, fldPath)
	return el
}

func ValidateIssuerConfig(iss *v1alpha1.IssuerConfig, fldPath *field.Path) field.ErrorList {
	numConfigs := 0
	el := field.ErrorList{}

	if iss.ACME != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("acme"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateACMEIssuerConfig(iss.ACME, fldPath.Child("acme"))...)
		}
	}
	if iss.CA != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("ca"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateCAIssuerConfig(iss.CA, fldPath.Child("ca"))...)
		}
	}
	if iss.SelfSigned != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("selfSigned"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateSelfSignedIssuerConfig(iss.SelfSigned, fldPath.Child("selfSigned"))...)
		}
	}
	if iss.Vault != nil {
		if numConfigs > 0 {
			el = append(el, field.Forbidden(fldPath.Child("vault"), "may not specify more than one issuer type"))
		} else {
			numConfigs++
			el = append(el, ValidateVaultIssuerConfig(iss.Vault, fldPath.Child("vault"))...)
		}
	}
	if numConfigs == 0 {
		el = append(el, field.Required(fldPath, "at least one issuer must be configured"))
	}

	return el
}

func ValidateACMEIssuerConfig(iss *v1alpha1.ACMEIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.Email) == 0 {
		el = append(el, field.Required(fldPath.Child("email"), "email address is a required field"))
	}
	if len(iss.PrivateKey.Name) == 0 {
		el = append(el, field.Required(fldPath.Child("privateKeySecretRef", "name"), "private key secret name is a required field"))
	}
	if len(iss.Server) == 0 {
		el = append(el, field.Required(fldPath.Child("server"), "acme server URL is a required field"))
	}
	if iss.HTTP01 != nil {
		el = append(el, ValidateACMEIssuerHTTP01Config(iss.HTTP01, fldPath.Child("http01"))...)
	}
	if iss.DNS01 != nil {
		el = append(el, ValidateACMEIssuerDNS01Config(iss.DNS01, fldPath.Child("dns01"))...)
	}
	return el
}

func ValidateCAIssuerConfig(iss *v1alpha1.CAIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.SecretName) == 0 {
		el = append(el, field.Required(fldPath.Child("secretName"), ""))
	}
	return el
}

func ValidateSelfSignedIssuerConfig(iss *v1alpha1.SelfSignedIssuer, fldPath *field.Path) field.ErrorList {
	return nil
}

func ValidateVaultIssuerConfig(iss *v1alpha1.VaultIssuer, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if len(iss.Server) == 0 {
		el = append(el, field.Required(fldPath.Child("server"), ""))
	}
	if len(iss.Path) == 0 {
		el = append(el, field.Required(fldPath.Child("path"), ""))
	}

	// check if caBundle is valid
	certs := iss.CABundle
	if len(certs) > 0 {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(certs)
		if !ok {
			el = append(el, field.Invalid(fldPath.Child("caBundle"), "", "Specified CA bundle is invalid"))
		}
	}

	return el
	// TODO: add validation for Vault authentication types
}

func ValidateACMEIssuerHTTP01Config(iss *v1alpha1.ACMEIssuerHTTP01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}

	if len(iss.ServiceType) > 0 {
		validTypes := []corev1.ServiceType{
			corev1.ServiceTypeClusterIP,
			corev1.ServiceTypeNodePort,
		}
		validType := false
		for _, validTypeName := range validTypes {
			if iss.ServiceType == validTypeName {
				validType = true
				break
			}
		}
		if !validType {
			el = append(el, field.Invalid(fldPath.Child("serviceType"), iss.ServiceType, fmt.Sprintf("optional field serviceType must be one of %q", validTypes)))
		}
	}

	return el
}

func ValidateACMEIssuerDNS01Config(iss *v1alpha1.ACMEIssuerDNS01Config, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	providersFldPath := fldPath.Child("providers")
	for i, p := range iss.Providers {
		fldPath := providersFldPath.Index(i)
		if len(p.Name) == 0 {
			el = append(el, field.Required(fldPath.Child("name"), "name must be specified"))
		}
		// allow empty values for now, until we have a MutatingWebhook to apply
		// default values to fields.
		if len(p.CNAMEStrategy) > 0 {
			switch p.CNAMEStrategy {
			case v1alpha1.NoneStrategy:
			case v1alpha1.FollowStrategy:
			default:
				el = append(el, field.Invalid(fldPath.Child("cnameStrategy"), p.CNAMEStrategy, fmt.Sprintf("must be one of %q or %q", v1alpha1.NoneStrategy, v1alpha1.FollowStrategy)))
			}
		}
		numProviders := 0

		var kind string
		var config interface{}
		var cfgPath *field.Path

		if p.Akamai != nil {
			numProviders++
			kind="akamai"
			config=p.Akamai
			cfgPath=fldPath.Child(kind)
		}
		if p.AzureDNS != nil {
			numProviders++
			kind="azuredns"
			config=p.AzureDNS
			cfgPath=fldPath.Child(kind)
		}
		if p.CloudDNS != nil {
			numProviders++
			kind="clouddns"
			config=p.CloudDNS
			cfgPath=fldPath.Child(kind)
		}
		if p.Cloudflare != nil {
			numProviders++
			kind="cloudflare"
			config=p.Cloudflare
			cfgPath=fldPath.Child(kind)
		}
		if p.Route53 != nil {
			numProviders++
			kind="route53"
			config=p.Route53
			cfgPath=fldPath.Child(kind)
		}
		if p.AcmeDNS != nil {
			numProviders++
			kind="acmedns"
			config=p.AcmeDNS
			cfgPath=fldPath.Child(kind)
		}

		if p.DigitalOcean != nil {
			numProviders++
			kind="digitalocean"
			config=p.DigitalOcean
			cfgPath=fldPath.Child(kind)
		}
		if p.RFC2136 != nil {
			numProviders++
			kind="rfc2136"
			config=p.RFC2136
			cfgPath=fldPath.Child(kind)
		}
		if p.Kind!=nil && *p.Kind!="" {
			if numProviders>0 {
				return append(el, field.Invalid(fldPath.Child("kind"), *p.Kind, "provider kind cannot be combiled with explicit provider config"))
			}
			numProviders++
			kind=*p.Kind
			config=p.ProviderConfig
			cfgPath=fldPath.Child("providerConfig")
		}
		if numProviders == 0 {
			el = append(el, field.Required(fldPath, "at least one provider must be configured"))
			return el
		}  else {
			if numProviders > 1 {
				el = append(el, field.Forbidden(fldPath, "may not specify more than one provider type"))
				return el
			}
		}

		factory:=dns.DefaultRegistry.Get(kind)
		if factory==nil {
			el = append(el, field.Invalid(fldPath, kind, fmt.Sprintf("unknown provider type %q", kind)))
		} else {
			glog.Infof("************ validating path %s", cfgPath)
			el = append(el, factory.Validate(config, cfgPath)...)
		}
	}
	return el
}

func ValidateSecretKeySelector(sks *v1alpha1.SecretKeySelector, fldPath *field.Path) field.ErrorList {
	el := field.ErrorList{}
	if sks.Name == "" {
		el = append(el, field.Required(fldPath.Child("name"), "secret name is required"))
	}
	if sks.Key == "" {
		el = append(el, field.Required(fldPath.Child("key"), "secret key is required"))
	}
	return el
}

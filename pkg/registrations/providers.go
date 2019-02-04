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

package registrations

// register all standard providers

import (
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/digitalocean"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"
_ "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
)



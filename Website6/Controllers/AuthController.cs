using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using IdentityModel;
using IdentityModel.Client;

namespace Website6.Controllers
{
    public class AuthController : Controller
    {
        public async Task<ActionResult> SignOut()
        {
            Request.GetOwinContext().Authentication.SignOut("Cookies", "TempCookie");

            using (var dc = new DiscoveryClient("http://auth.sso.com") { Policy = { RequireHttps = false } })
            {
                var disco = await dc.GetAsync();

                return Redirect(disco.EndSessionEndpoint);
            }
        }

        [AllowAnonymous]
        public void OidcSignOut(string sid)
        {
            if (!User.Identity.IsAuthenticated)
                return;

            var cp = (ClaimsPrincipal) User;
            var sidClaim = cp.FindFirst("sid");
            if (sidClaim != null && sidClaim.Value == sid)
            {
                Request.GetOwinContext().Authentication.SignOut("Cookies");
            }
        }

        public async Task<ActionResult> SignIn()
        {
            using (var dc = new DiscoveryClient("http://auth.sso.com") { Policy = { RequireHttps = false } })
            {
                var disco = await dc.GetAsync();
                var ar = new RequestUrl(disco.AuthorizeEndpoint);

                var state = Guid.NewGuid().ToString("N");
                var nonce = Guid.NewGuid().ToString("N");

                var tempId = new ClaimsIdentity("TempCookie");
                tempId.AddClaim(new Claim("state", state));
                tempId.AddClaim(new Claim("nonce", nonce));

                Request.GetOwinContext().Authentication.SignIn(tempId);

                return Redirect(ar.CreateAuthorizeUrl(
                    clientId: "website6",
                    responseType: "code",
                    scope: "openid profile email offline_access dummy",
                    redirectUri: "http://website6.sso/Auth/SignInCallback",
                    state: state,
                    nonce: nonce,
                    responseMode: "form_post"
                ));
            }
        }

        [HttpPost]
        public async Task<ActionResult> SignInCallback()
        {
            var code = Request.Form["code"];
            var state = Request.Form["state"];
            var sessionState = Request.Form["session_state"];
            var error = Request.Form["error"];

            if (!string.IsNullOrEmpty(error))
                throw new Exception(error);

            var tempResult = await Request.GetOwinContext().Authentication.AuthenticateAsync("TempCookie");

            if (tempResult == null)
                throw new Exception("missing temp cookie");

            if (!string.Equals(state, tempResult.Identity.FindFirst("state").Value))
                throw new Exception("invalid state value");

            var ac = await ValidateAuthorizationCode(code);

            var id = await ValidateJwt(ac.First(c => c.Type == "id_token").Value, "id");
            var at = await ValidateJwt(ac.First(c => c.Type == "token").Value, "access");

            if (!string.Equals(id.FindFirst("nonce")?.Value, tempResult.Identity.FindFirst("nonce").Value))
                throw new Exception("invalid nonce");

            var ci = new ClaimsIdentity("Cookies");
            ci.AddClaims(id.Claims);
            ci.AddClaims(at.Claims);
            ci.AddClaims(ac);
            ci.AddClaim(new Claim("session_state", sessionState));

            Request.GetOwinContext().Authentication.SignIn(ci);

            return Redirect("/");
        }

        private async Task<ICollection<Claim>> ValidateAuthorizationCode(string authorizationCode)
        {
            // read discovery document to find issuer and key material
            using (var dc = new DiscoveryClient("http://auth.sso.com") { Policy = { RequireHttps = false } })
            {
                var disco = await dc.GetAsync();

                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["redirect_uri"] = "http://website6.sso/Auth/SignInCallback",
                    ["code"] = authorizationCode,
                    ["client_id"] = "website6",
                    ["client_secret"] = "secret"
                });

                using (var client = new HttpClient())
                using (var response = await client.PostAsync(disco.TokenEndpoint, content))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception("something went wrong... - debug here");
                    }

                    var data = await response.Content.ReadAsStringAsync();
                    var tr = new TokenResponse(response.StatusCode, response.ReasonPhrase, data);

                    return new List<Claim>
                    {
                        new Claim("token", tr.AccessToken),
                        new Claim("id_token", tr.IdentityToken),
                        new Claim("refresh_token", tr.RefreshToken),
                        new Claim("expires_at", DateTimeOffset.UtcNow.AddSeconds(tr.ExpiresIn).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
                    };
                }
            }
        }

        private async Task<ClaimsPrincipal> ValidateJwt(string jwt, string tokenType)
        {
            using (var dc = new DiscoveryClient("http://auth.sso.com") { Policy = { RequireHttps = false } })
            {
                var disco = await dc.GetAsync();

                var ists = disco.KeySet.Keys.Where(k => k.X5c.Any()).Select(k => new X509SecurityToken(new X509Certificate2(Base64Url.Decode(k.X5c.First())))).ToList();

                var parameters = new TokenValidationParameters
                {
                    ValidIssuer = disco.Issuer,
                    ValidAudience = tokenType == "id" ? "website6" : disco.Issuer + "/resources",
                    IssuerSigningTokens = ists,

                    NameClaimType = JwtClaimTypes.Name,
                    RoleClaimType = JwtClaimTypes.Role
                };

                var handler = new JwtSecurityTokenHandler();
                var user = handler.ValidateToken(jwt, parameters, out var _);

                return user;
            }
        }
    }
}
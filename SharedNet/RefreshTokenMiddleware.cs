using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;

namespace SharedNet
{

    public class RefreshTokenOptions
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string RefreshTokenClaimName { get; set; } = "refresh_token";
        public string ExpiresAtClaimName { get; set; } = "expires_at";
        public ISystemClock SystemClock { get; set; } = new SystemClock();
        public string MetadataAddress { get; set; }
        public OpenIdConnectConfiguration Configuration { get; set; }
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();
        public SecurityTokenHandlerCollection SecurityTokenHandlers { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(10);
    }

    public class RefreshTokenMiddleware : OwinMiddleware
    {
        private OpenIdConnectConfiguration configuration;
        private RefreshTokenOptions Options { get; }

        public RefreshTokenMiddleware(OwinMiddleware next, RefreshTokenOptions options) : base(next)
        {
            Options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            // TODO w przypadku niepowodzenia odświeżenie wylogować w cholerę

            var cp = context.Request.User as ClaimsPrincipal;

            if (cp?.Identity == null || !cp.Identity.IsAuthenticated)
            {
                await Next.Invoke(context);

                return;
            }

            var refreshTokenClaim = cp.FindFirst(Options.RefreshTokenClaimName);
            var expiresAtClaim = cp.FindFirst(Options.ExpiresAtClaimName);

            if (refreshTokenClaim == null || expiresAtClaim == null)
            {
                await Next.Invoke(context);

                return;
            }

            var expiresAt = long.Parse(expiresAtClaim.Value);

            // TODO zrobić konf. dla "+1"
            if (Options.SystemClock.UtcNow.ToUnixTimeSeconds() < expiresAt - 1)
            {
                await Next.Invoke(context);

                return;
            }

            if (configuration == null)
            {
                configuration = await Options.ConfigurationManager.GetConfigurationAsync(context.Request.CallCancelled);
            }
            
            TokenResponse tr;

            // TODO new WebRequestHandler() -> coś w rodzaju Options.BackchannelHttpHandler
            using (var client = new TokenClient(configuration.TokenEndpoint, Options.ClientId, Options.ClientSecret, new WebRequestHandler()))
            {
                tr = await client.RequestRefreshTokenAsync(refreshTokenClaim.Value, cancellationToken: context.Request.CallCancelled);

                // TODO logging
                if (tr.IsError)
                {
                    await Next.Invoke(context);

                    return;
                }


                if (string.IsNullOrEmpty(tr.IdentityToken))
                {
                    await Next.Invoke(context);

                    return;
                }
            }

            var issuers = new[] { configuration.Issuer };
            var tvp = Options.TokenValidationParameters.Clone();

            tvp.ValidIssuers = tvp.ValidIssuers?.Concat(issuers) ?? issuers;
            tvp.IssuerSigningTokens = tvp.IssuerSigningTokens?.Concat(configuration.SigningTokens) ?? configuration.SigningTokens;

            var principal = Options.SecurityTokenHandlers.ValidateToken(tr.IdentityToken, tvp, out SecurityToken validatedToken);
            var claimsIdentity = (ClaimsIdentity) principal.Identity;
            // TODO wykorzystac
            var jwt = validatedToken as JwtSecurityToken;

            claimsIdentity.AddClaim(new Claim("id_token", tr.IdentityToken));

            if (!string.IsNullOrEmpty(tr.AccessToken))
            {
                var eat = DateTimeOffset.UtcNow.AddSeconds(tr.ExpiresIn).ToUnixTimeSeconds();

                claimsIdentity.AddClaim(new Claim("token", tr.AccessToken));
                claimsIdentity.AddClaim(new Claim("expires_at", eat.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
            }

            if (!string.IsNullOrEmpty(tr.RefreshToken))
            {
                claimsIdentity.AddClaim(new Claim("refresh_token", tr.RefreshToken));
            }

            context.Authentication.SignIn(new AuthenticationProperties
            {
                IsPersistent = true
            }, claimsIdentity);

            await Next.Invoke(context);
        }
    }
}
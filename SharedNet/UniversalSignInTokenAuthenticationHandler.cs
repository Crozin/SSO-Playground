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
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace SharedNet
{
    public class UniversalSignInTokenAuthnticationOptions : AuthenticationOptions
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string CookieName { get; set; } = "usic";
        public string GrantType { get; set; } = "universal_signin";
        public string Scope { get; set; }

        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();
        public ISystemClock SystemClock { get; set; } = new SystemClock();
        public string MetadataAddress { get; set; }
        public OpenIdConnectConfiguration Configuration { get; set; }
        public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; }
        public SecurityTokenHandlerCollection SecurityTokenHandlers { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public UniversalSignInTokenAuthnticationOptions() : this("UniversalSignInToken") { }
        public UniversalSignInTokenAuthnticationOptions(string authenticationType) : base(authenticationType) { }
    }

    public class UniversalSignInTokenAuthenticationHandler : AuthenticationHandler<UniversalSignInTokenAuthnticationOptions>
    {
        private OpenIdConnectConfiguration configuration;

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // TODO usuwać to ciacho przy zużyciu
            // TODO w przypadku niepowodzenia po prostu zignorować

            var identity = Context.Authentication.User?.Identity;

            if (identity != null && identity.IsAuthenticated)
            {
                return null;
            }

            var usiToken = Context.Request.Cookies[Options.CookieName];

            if (string.IsNullOrEmpty(usiToken))
            {
                return null;
            }

            if (configuration == null)
            {
                configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
            }

            TokenResponse rttr;
            string sid;

            // TODO new WebRequestHandler() -> coś w rodzaju Options.BackchannelHttpHandler
            using (var tc = new TokenClient(configuration.TokenEndpoint, Options.ClientId, Options.ClientSecret, new WebRequestHandler()))
            {
                var ustr = await tc.RequestCustomGrantAsync(Options.GrantType, Options.Scope, new { Token = usiToken });

                if (ustr.IsError)
                    throw new Exception(ustr.Error);

                sid = ustr.Json["__delegating_sid"]?.ToObject<string>();

                rttr = await tc.RequestRefreshTokenAsync(ustr.RefreshToken);

                if (rttr.IsError)
                    throw new Exception(ustr.Error);
            }

            var issuers = new[] { configuration.Issuer };
            var tvp = Options.TokenValidationParameters.Clone();

            tvp.ValidIssuers = tvp.ValidIssuers?.Concat(issuers) ?? issuers;
            tvp.IssuerSigningTokens = tvp.IssuerSigningTokens?.Concat(configuration.SigningTokens) ?? configuration.SigningTokens;

            var principal = Options.SecurityTokenHandlers.ValidateToken(rttr.IdentityToken, tvp, out SecurityToken validatedToken);
            var claimsIdentity = (ClaimsIdentity)principal.Identity;
            // TODO wykorzystac
            var jwt = validatedToken as JwtSecurityToken;

            claimsIdentity.AddClaim(new Claim("id_token", rttr.IdentityToken));

            if (!string.IsNullOrEmpty(rttr.AccessToken))
            {
                var eat = DateTimeOffset.UtcNow.AddSeconds(rttr.ExpiresIn).ToUnixTimeSeconds();

                claimsIdentity.AddClaim(new Claim("token", rttr.AccessToken));
                claimsIdentity.AddClaim(new Claim("expires_at", eat.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
            }

            if (!string.IsNullOrEmpty(rttr.RefreshToken))
            {
                claimsIdentity.AddClaim(new Claim("refresh_token", rttr.RefreshToken));
            }

            if (!string.IsNullOrEmpty(sid) && claimsIdentity.Claims.All(c => c.Type != "sid"))
            {
                claimsIdentity.AddClaim(new Claim("sid", sid));
            }

            return new AuthenticationTicket(claimsIdentity, null);
        }
    }

    public class UniversalSignInTokenAuthnticationMiddleware : AuthenticationMiddleware<UniversalSignInTokenAuthnticationOptions>
    {
        public UniversalSignInTokenAuthnticationMiddleware(OwinMiddleware next, IAppBuilder app, UniversalSignInTokenAuthnticationOptions options) : base(next, options)
        {
            // Default configuration based on UseOpenIdConnectAuthenticationMiddleware

            if (string.IsNullOrWhiteSpace(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrWhiteSpace(options.ClientId))
            {
                options.TokenValidationParameters.ValidAudience = options.ClientId;
            }

            if (options.SecurityTokenHandlers == null)
            {
                options.SecurityTokenHandlers = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            }

            if (options.Configuration != null)
            {
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(options.MetadataAddress) && !string.IsNullOrWhiteSpace(options.Authority))
                {
                    options.MetadataAddress = options.Authority;

                    if (!options.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                    {
                        options.MetadataAddress += "/";
                    }

                    options.MetadataAddress += ".well-known/openid-configuration";
                }

                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new HttpClient(ResolveHttpMessageHandler(options))
                {
                    Timeout = Options.BackchannelTimeout,
                    MaxResponseContentBufferSize = 10485760L
                });
            }
        }

        protected override AuthenticationHandler<UniversalSignInTokenAuthnticationOptions> CreateHandler()
        {
            return new UniversalSignInTokenAuthenticationHandler();
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(UniversalSignInTokenAuthnticationOptions options)
        {
            var httpMessageHandler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                ((WebRequestHandler)httpMessageHandler).ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return httpMessageHandler;
        }
    }
}

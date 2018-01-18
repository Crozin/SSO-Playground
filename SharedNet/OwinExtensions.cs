using System;
using System.Net.Http;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;
using SharedNet;

// ReSharper disable once CheckNamespace
namespace Owin
{
    public static class RefreshTokenExtensions
    {
        public static IAppBuilder UseRefreshToken(this IAppBuilder app, RefreshTokenOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (options == null)
                throw new ArgumentNullException(nameof(options));

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
                    Timeout = options.BackchannelTimeout,
                    MaxResponseContentBufferSize = 10485760L
                });
            }

            return app.Use<RefreshTokenMiddleware>(options);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(RefreshTokenOptions options)
        {
            var httpMessageHandler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                ((WebRequestHandler) httpMessageHandler).ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return httpMessageHandler;
        }
    }

    public static class UniversalSignInTokenAuthenticationExtensions
    {
        public static IAppBuilder UseUniversalSignInTokenAuthentication(this IAppBuilder app, UniversalSignInTokenAuthnticationOptions universalSignInTokenOptions)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (universalSignInTokenOptions == null)
                throw new ArgumentNullException(nameof(universalSignInTokenOptions));

            return app.Use(typeof(UniversalSignInTokenAuthnticationMiddleware), app, universalSignInTokenOptions);
        }
    }
}
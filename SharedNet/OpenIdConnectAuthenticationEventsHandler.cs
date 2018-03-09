using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json;
using NLog;

namespace SharedNet
{
    public class OpenIdConnectAuthenticationEventsHandler
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public static Func<AuthorizationCodeReceivedNotification, Task> HandleAuthorizationCodeReceived(Action<List<UniversalSignInCodeDto>> processUniversalSignInAddresses)
        {
            return async n =>
            {
                var configuration = await n.Options.ConfigurationManager.GetConfigurationAsync(n.OwinContext.Request.CallCancelled);
                
                // TODO new WebRequestHandler() -> coś w rodzaju Options.BackchannelHttpHandler
                using (var wh = new WebRequestHandler { ServerCertificateCustomValidationCallback = (message, certificate2, arg3, arg4) => true })
                using (var tc = new TokenClient(configuration.TokenEndpoint, n.Options.ClientId, n.Options.ClientSecret, wh))
                using (var uic = new UserInfoClient(configuration.UserInfoEndpoint, wh))
                {
                    var owinRequest = n.OwinContext.Request;

                    var tr = await tc.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri, null, new
                    {
                        end_user_ip = owinRequest.RemoteIpAddress,
                        end_user_user_agent = owinRequest.Headers.Get("User-Agent")
                    });

                    Logger.Info("TR RAW: " + tr.Raw);

                    if (tr.IsError)
                        throw new Exception(tr.Error);

                    var uir = await uic.GetAsync(tr.AccessToken);

                    Logger.Info("UIR RAW: " + uir.Raw);

                    if (uir.IsError)
                        throw new Exception(uir.Error);

                    // TODO wykorzystac uir?

                    var us = tr.Json["universal_sign_in"]?.ToObject<List<UniversalSignInCodeDto>>();

                    if (processUniversalSignInAddresses != null && us != null)
                    {
                        processUniversalSignInAddresses(us);
                    }

                    var claimsIdentity = n.AuthenticationTicket.Identity;

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
                }
            };
        }

        public static Func<RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> HandleRedirectToIdentityProvider(string arcValues = null)
        {
            return n =>
            {
                if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.AuthenticationRequest && !string.IsNullOrEmpty(arcValues))
                {
                    n.ProtocolMessage.AcrValues = arcValues;
                }

                if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                {
                    n.ProtocolMessage.IdTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                }

                return Task.CompletedTask;
            };
        }
    }

    public class UniversalSignInCodeDto
    {
        [JsonProperty("target_uri")]
        public string TargetUri { get; set; }

        [JsonProperty("code")]
        public string Code { get; set; }
    }
}

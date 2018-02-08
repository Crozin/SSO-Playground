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

namespace SharedNet
{
    public class OpenIdConnectAuthenticationEventsHandler
    {
        public static Func<AuthorizationCodeReceivedNotification, Task> HandleAuthorizationCodeReceived(Action<List<string>> processUniversalSignInAddresses)
        {
            return async n =>
            {
                var configuration = await n.Options.ConfigurationManager.GetConfigurationAsync(n.OwinContext.Request.CallCancelled);

                // TODO new WebRequestHandler() -> coś w rodzaju Options.BackchannelHttpHandler
                using (var tc = new TokenClient(configuration.TokenEndpoint, n.Options.ClientId, n.Options.ClientSecret, new WebRequestHandler()))
                using (var uic = new UserInfoClient(configuration.UserInfoEndpoint, new WebRequestHandler()))
                {
                    var tr = await tc.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri);

                    if (tr.IsError)
                        throw new Exception(tr.Error);

                    var uir = await uic.GetAsync(tr.AccessToken);

                    if (uir.IsError)
                        throw new Exception(uir.Error);

                    // TODO wykorzystac uir?

                    var us = tr.Json["universal_signin"]?.ToObject<List<string>>();

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
}

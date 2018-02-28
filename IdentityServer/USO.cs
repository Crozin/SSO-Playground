using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AutoMapper.Configuration;
using IdentityServer.Services;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;
using IdentityServer3.EntityFramework;
using EntitiesMap = IdentityServer3.EntityFramework.Entities.EntitiesMap;

namespace IdentityServer
{
    public class X_UniversalSignInGrantValidator : ICustomGrantValidator
    {
        public async Task<CustomGrantValidationResult> ValidateAsync(ValidatedTokenRequest request)
        {
            await Task.Delay(1);

            var token = request.Raw.Get("universal_signin_token");
            var ip = request.Raw.Get("end_user_ip");
            var ua = request.Raw.Get("end_user_user_agent");

            return new CustomGrantValidationResult();
        }

        public string GrantType => "universal_signin";
    }

    public class X_CustomTokenResponseGenerator : ICustomTokenResponseGenerator
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        private readonly IClientStore clientStore;
        private readonly IUniversalSignInCodeStore universalSignInCodeStore;
        private readonly IDictionary<string, string> unversalSignInClients;

        public X_CustomTokenResponseGenerator(IClientStore clientStore, IUniversalSignInCodeStore universalSignInCodeStore, IDictionary<string, string> unversalSignInClients)
        {
            this.clientStore = clientStore;
            this.universalSignInCodeStore = universalSignInCodeStore;
            this.unversalSignInClients = unversalSignInClients;
        }

        public async Task<TokenResponse> GenerateAsync(ValidatedTokenRequest request, TokenResponse response)
        {
            if (request.GrantType != Constants.GrantTypes.AuthorizationCode || !unversalSignInClients.ContainsKey(request.Client.ClientId))
            {
                return response;
            }

            var ip = request.Raw.Get("end_user_ip");
            var ua = request.Raw.Get("end_user_user_agent");
            var idToken = new JwtSecurityToken(response.IdentityToken);

            if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(ua))
            {
                // todo zalogować tutaj coś na poziomie WARN

                return response;
            }

            var result = new List<string>();

            foreach (var kvp in unversalSignInClients)
            {
                var clientId = kvp.Key;
                var uri = kvp.Value;
                var glue = uri.Contains("?") ? "&" : "?";
                var client = await clientStore.FindClientByIdAsync(clientId).ConfigureAwait(false);

                var key = GenerateUniqueToken();
//                var token = new UniversalSignInToken(
//                    idToken.Subject, 
//                    idToken.Claims.First(c => c.Type == Constants.ClaimTypes.SessionId).Value,
//                    DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 
//                    ip, 
//                    ua
//                );

                var token = new UniversalSignInCode
                {
                    Client = client,
                    Subject = new ClaimsPrincipal(new ClaimsIdentity(idToken.Claims)),
                    EndUserIp = ip,
                    EndUserUserAgent = ua
                };

                result.Add(uri + glue + "token=" + key);

                await universalSignInCodeStore.StoreAsync(key, token).ConfigureAwait(false);
            }

            response.Custom.Add("universal_signin_uris", result);

            return response;
        }

        private string GenerateUniqueToken()
        {
            var bytes = new byte[256];

            Rng.GetBytes(bytes);

            return BitConverter.ToString(bytes);
        }
    }

    public interface X_UniversalSignInClientStore
    {
        Task<List<Client>> FindAllUniversalSignInClientsAsync();
    }

    public class X_ClientSore : ClientStore, X_UniversalSignInClientStore
    {
        private readonly IClientConfigurationDbContext context;
        private readonly EntityFrameworkServiceOptions options;

        public X_ClientSore(IClientConfigurationDbContext context) : base(context)
        {
            this.context = context;
        }

        public X_ClientSore(EntityFrameworkServiceOptions options, IClientConfigurationDbContext context) : base(options, context)
        {
            this.context = context;
            this.options = options;
        }

        public async Task<List<Client>> FindAllUniversalSignInClientsAsync()
        {
            var query = context.Clients
                .Include(x => x.ClientSecrets)
                .Include(x => x.RedirectUris)
                .Include(x => x.PostLogoutRedirectUris)
                .Include(x => x.AllowedScopes)
                .Include(x => x.IdentityProviderRestrictions)
                .Include(x => x.Claims)
                .Include(x => x.AllowedCustomGrantTypes)
                .Include(x => x.AllowedCorsOrigins)
                .Where(x => x.ClientSecrets.Any(cs => cs.Type == "universal_signin"));

            List<IdentityServer3.EntityFramework.Entities.Client> clients;

            if (options != null && options.SynchronousReads)
            {
                clients = query.ToList();
            }
            else
            {
                clients = await query.ToListAsync().ConfigureAwait(false);
            }

            return clients.Select(EntitiesMap.ToModel).ToList();
        }
    }
}
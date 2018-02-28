using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.EntityFramework;
using IdentityServer3.EntityFramework.Entities;

namespace IdentityServer.Services
{
    public class UniversalSignInCodeStore : BaseTokenStore<UniversalSignInCode>, IUniversalSignInCodeStore
    {
        private const TokenType UniversalSignInCodeType = (TokenType) 99; // TODO hacky, rename

        public UniversalSignInCodeStore(IOperationalDbContext context, IScopeStore scopeStore, IClientStore clientStore)
            : base(context, UniversalSignInCodeType, scopeStore, clientStore)
        {
        }

        public UniversalSignInCodeStore(EntityFrameworkServiceOptions options, IOperationalDbContext context, IScopeStore scopeStore, IClientStore clientStore)
            : base(options, context, UniversalSignInCodeType, scopeStore, clientStore)
        {
        }

        public override async Task StoreAsync(string key, UniversalSignInCode code)
        {
            var tokenEntity = new IdentityServer3.EntityFramework.Entities.Token
            {
                Key = key,
                SubjectId = code.SubjectId,
                ClientId = code.ClientId,
                JsonCode = ConvertToJson(code),
                Expiry = DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(30)), // TODO konfigurowalne na podstawie właściwości klienta? Albo raczej globalny (konstruktor), współny wpis?
                TokenType = tokenType
            };

            context.Tokens.Add(tokenEntity);

            await context.SaveChangesAsync();
        }
    }

    public interface IUniversalSignInCodeStore : ITransientDataRepository<UniversalSignInCode> { }

    public class UniversalSignInCode : ITokenMetadata
    {
        public IdentityServer3.Core.Models.Client Client { get; set; }
        public ClaimsPrincipal Subject { get; set; }
        public DateTimeOffset CreationTime { get; set; }
        public string EndUserIp { get; set; }
        public string EndUserUserAgent { get; set; }

        public UniversalSignInCode()
        {
            CreationTime = DateTimeOffset.UtcNow;
        }

        public string SubjectId => Subject.GetSubjectId();
        public string ClientId => Client.ClientId;
        public IEnumerable<string> Scopes => new[] { "abc" }; // TODO różni klienci mogą chcieć różne? Pewnie będą one przesyłane w faktycznym żądaniu?
    }
}
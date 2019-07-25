using RefreshTokensWebApiExample.DataAccess;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RefreshTokensWebApiExample.Services
{
    public class TokenValidatorService
    {
        private readonly UsersDb usersDb;
        private readonly ITokenService tokenService;

        public TokenValidatorService(UsersDb usersDb,ITokenService tokenService)
        {
            this.usersDb = usersDb;
            this.tokenService = tokenService;
        }

        public User AuthenticateUser(string token)
        {
            var principal = tokenService.GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name; //this is mapped to the Name claim by default
            var user = this.usersDb.Users.Where(u=>u.Username==username).FirstOrDefault();
            if (user.AccessToken != token) return null;
            return user;
        }
    }
}

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using RefreshTokensWebApiExample.DataAccess;
using RefreshTokensWebApiExample.Services;
using System;
using System.Net;

namespace RefreshTokensWebApiExample.Filters
{
    public class AuthFilterscs : Attribute, IAuthorizationFilter
    {
        public AuthFilterscs(TokenValidatorService tokenValidatorService)
        {
            _tokenValidatorService = tokenValidatorService;
        }

        private readonly TokenValidatorService _tokenValidatorService;

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (context != null)
            {
                if (context.HttpContext.Response.Headers.ContainsKey("Token-Expired"))
                {
                    context.HttpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Result = new JsonResult("") { Value = new { Error = "User is not logged in" } };
                    return;
                }
                if (context.HttpContext.Request.Headers.ContainsKey("Authorization"))
                {
                    Microsoft.Extensions.Primitives.StringValues accessToken_Bearear = context.HttpContext.Request.Headers["Authorization"];
                    User User = _tokenValidatorService.AuthenticateUser(accessToken_Bearear.ToString().Split("Bearer")[1]?.Trim());
                    if (User != null)
                    {
                        // nothing to do
                    }
                    else
                    {
                        context.Result = new JsonResult("") { Value = new { Error = "User is not logged in" } };
                    }
                }
            }
        }


    }
}

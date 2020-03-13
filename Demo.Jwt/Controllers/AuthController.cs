using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtServer.Controllers
{
    [Route("api/[controller]/[Action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        [AllowAnonymous]
        [HttpGet]
        [Route("api/nopermission")]
        public IActionResult NoPermission()
        {
            return Forbid("No Permission!");
        }

        [HttpGet]
        public IActionResult Get(string userName, string pwd)
        {
            if (CheckAccount(userName, pwd, out string role))
            {
                Const.ValidAudience = userName + pwd;
                var claims = new[]
                {
                    // not before 声明标识了JWT之前的时间不做处理
                    new Claim(JwtRegisteredClaimNames.Nbf,$"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}"),

                    // Expiration Time 过期时间
                    new Claim(JwtRegisteredClaimNames.Exp,$"{new DateTimeOffset(DateTime.Now.AddMinutes(30)).ToUnixTimeSeconds()}"),
                    new Claim(ClaimTypes.NameIdentifier,userName),
                    new Claim("Role", role)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Const.SecurityKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: Const.Domain,
                    audience: Const.ValidAudience,
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }
            else
            {
                return BadRequest(new { message = "it is wrong." });
            }
        }
        /// <summary>
        /// 模拟登陆校验，因为是模拟，所以逻辑很‘模拟’
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="pwd"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        private bool CheckAccount(string userName, string pwd, out string role)
        {
            role = "user";

            if (string.IsNullOrEmpty(userName))
                return false;

            if (userName.Equals("admin"))
                role = "admin";

            return true;

        }
    }
}
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using JwtTest.Models;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JwtTest.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class JwtAuthController : ControllerBase
    {
        private readonly FakeDbContext _fakeDbContext;
        private readonly JwtHelper _jwtHelper;

        public JwtAuthController(FakeDbContext fakeDbContext, JwtHelper jwtHelper)
        {
            this._fakeDbContext = fakeDbContext;
            this._jwtHelper = jwtHelper;
        }

        /// <summary>
        /// 登入
        /// </summary>
        /// <param name="user">帳號、密碼</param>
        /// <returns>JWT Token</returns>
        [AllowAnonymous]
        [HttpPost("~/signin")]
        [ProducesResponseType(200, Type = typeof(string))]
        public IActionResult SignIn(UserDto user)
        {
            AuthDto authDto = ValidateUser(user);

            if (authDto != null)
            {
                string token = this._jwtHelper.GenerateToken(authDto);

                return Ok(token);
            }
            else
            {
                return BadRequest();
            }
        }

        private AuthDto ValidateUser(UserDto user)
        {
            //比對方式 使用 C# 9 record
            if (this._fakeDbContext.Users.Any(item => item == user))
            {
                return _fakeDbContext.Auths.Single(item => item.Username == user.Username);
            }

            ////比對方式 使用 class
            //if (this._fakeDbContext.Users.Any(item => item.Username == user.Username && item.Password == user.Password))
            //{
            //    return _fakeDbContext.Auths.Single(item => item.Username == user.Username);
            //}

            return null;
        }

        /// <summary>
        /// 取得目前登入帳號的聲明(Claim)內容
        /// </summary>
        /// <returns>JWT Payload</returns>
        [HttpGet("~/claims")]
        [ProducesResponseType(200, Type = typeof(Dictionary<string, string>))]
        public IActionResult GetClaims()
        {
            return Ok(User.Claims.ToDictionary(k => k.Type, v => v.Value));
        }

        /// <summary>
        /// 取得目前登入帳號的名稱
        /// </summary>
        /// <returns>帳號名稱</returns>
        [HttpGet("~/userName")]
        [ProducesResponseType(200, Type = typeof(string))]
        public IActionResult GetUserName()
        {
            return Ok(User.Identity.Name);
        }

        /// <summary>
        /// 取得目前登入帳號的權限
        /// </summary>
        /// <returns>帳號權限</returns>
        [HttpGet("~/userRole")]
        [ProducesResponseType(200, Type = typeof(string))]
        public IActionResult GetUserRole()
        {
            Claim roleClaim = User.Claims.FirstOrDefault(p => p.Type == ClaimTypes.Role);

            return Ok(roleClaim.Value);
        }

        /// <summary>
        /// 取得jwt id
        /// </summary>
        /// <returns>jwt id</returns>
        [HttpGet("~/jwtID")]
        [ProducesResponseType(200, Type = typeof(string))]
        public IActionResult GetUniqueId()
        {
            Claim jtiClaim = User.Claims.FirstOrDefault(p => p.Type == JwtRegisteredClaimNames.Jti);

            return Ok(jtiClaim.Value);
        }

        /// <summary>
        /// 取得帳號權限清單
        /// </summary>
        /// <returns>權限清單</returns>
        [HttpGet("~/getAuths")]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(200, Type = typeof(IEnumerable<AuthDto>))]
        public IActionResult GetAuths()
        {
            return Ok(this._fakeDbContext.Auths);
        }

        /// <summary>
        /// 設定帳號權限
        /// </summary>
        /// <remarks>
        ///    範例:
        ///    POST
        ///    {
        ///     "username": "jack",
        ///     "auth": "Auth"
        ///    }
        /// </remarks>
        /// <param name="dto"></param>
        /// <returns></returns>
        [HttpPost("~/setAuth")]
        [Authorize(Roles = "Admin")]
        public IActionResult SetAuth([FromBody] AuthDto dto)
        {
            var authInDb = this._fakeDbContext.Auths.SingleOrDefault(w => w.Username == dto.Username);

            if (authInDb != null)
            {
                authInDb.Auth = dto.Auth;

                return Ok();
            }

            return BadRequest();
        }
    }
}

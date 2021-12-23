using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

using JwtTest.Models;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtTest
{
    public record JwtSettings
    {
        public string Issuer { get; init; }

        public string SignKey { get; init; }

        public int ExpireMinutes { get; init; }
    }

    public class JwtHelper
    {
        private readonly JwtSettings _settings;

        public JwtHelper(
            IOptions<JwtSettings> optionsSettings,
            IOptionsSnapshot<JwtSettings> optionsSnapshotSettings)
        {
            this._settings = optionsSettings?.Value;

            this._settings = optionsSnapshotSettings?.Value;
        }

        public string GenerateToken(AuthDto authDto)
        {
            // 設定要加入到 JWT Token 中的聲明資訊(Claims)
            Claim[] claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, _settings.Issuer),
                new Claim(JwtRegisteredClaimNames.Sub, authDto.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID
                new Claim(ClaimTypes.Role, authDto.Auth), //role
            };

            var userClaimsIdentity = new ClaimsIdentity(claims);

            // 建立一組對稱式加密的金鑰，主要用於 JWT 簽章之用
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SignKey));

            // HmacSha256 有要求必須要大於 128 bits，所以 key 不能太短，至少要 16 字元以上
            // https://stackoverflow.com/questions/47279947/idx10603-the-algorithm-hs256-requires-the-securitykey-keysize-to-be-greater
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            // 建立 SecurityTokenDescriptor
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Issuer = _settings.Issuer,
                //Audience = issuer, // 由於你的 API 受眾通常沒有區分特別對象，因此通常不太需要設定，也不太需要驗證
                //NotBefore = DateTime.Now, // 預設值就是 DateTime.Now
                //IssuedAt = DateTime.Now, // 預設值就是 DateTime.Now
                Subject = userClaimsIdentity,
                Expires = DateTime.Now.AddMinutes(_settings.ExpireMinutes),
                SigningCredentials = signingCredentials
            };

            // 產出所需要的 JWT securityToken 物件，並取得序列化後的 Token 結果(字串格式)
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var serializeToken = tokenHandler.WriteToken(securityToken);

            return serializeToken;
        }
    }

    public class ConfigureJwtBearerOptions : IConfigureOptions<JwtBearerOptions>
    {
        private readonly JwtSettings _settings;

        public ConfigureJwtBearerOptions(IConfiguration configuration)
        {
            this._settings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
        }

        public void Configure(JwtBearerOptions options)
        {
            // 當驗證失敗時，回應標頭會包含 WWW-Authenticate 標頭，這裡會顯示失敗的詳細錯誤原因
            options.IncludeErrorDetails = true; // 預設值為 true，有時會特別關閉

            options.TokenValidationParameters = new TokenValidationParameters
            {
                // 透過這項宣告，就可以從 "sub" 取值並設定給 User.Identity.Name
                NameClaimType = ClaimTypes.NameIdentifier,
                // 透過這項宣告，就可以從 "roles" 取值，並可讓 [Authorize] 判斷角色
                RoleClaimType = ClaimTypes.Role,

                // 一般我們都會驗證 Issuer
                ValidateIssuer = true,
                ValidIssuer = _settings.Issuer,

                // 通常不太需要驗證 Audience
                ValidateAudience = false,
                //ValidAudience = "JwtAuthDemo", // 不驗證就不需要填寫

                // 一般我們都會驗證 Token 的有效期間
                ValidateLifetime = true,

                // 如果 Token 中包含 key 才需要驗證，一般都只有簽章而已
                ValidateIssuerSigningKey = false,

                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SignKey))
            };
        }
    }


}
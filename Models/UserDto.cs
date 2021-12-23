using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTest.Models
{
    // C# 9 record 並非簡單屬性 POCO 的語法糖 https://ithelp.ithome.com.tw/articles/10254422?sc=rss.qu
    public record UserDto
    {
        [Required]
        public string Username { get; init; }

        [Required]
        public string Password { get; init; }
    }
}

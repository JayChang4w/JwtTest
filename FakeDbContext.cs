using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using JwtTest.Models;

namespace JwtTest
{
    public class FakeDbContext
    {
        public FakeDbContext()
        {
            this.Users = new List<UserDto>()
            {
                new () { Username = "jay", Password = "Foo-Pw"},
                new () { Username = "alan", Password =  "Foo-Pw"},
                new () { Username = "albert", Password =  "Foo-Pw"},
            };

            this.Auths = new List<AuthDto>()
            {
                new AuthDto() { Username = "jack", Auth = "Admin" },
                new AuthDto() { Username = "albert", Auth = "User" },
                new AuthDto() { Username = "alan", Auth = "User" },
            };
        }

        public IEnumerable<UserDto> Users { get; set; }

        public IEnumerable<AuthDto> Auths { get; set; }
    }
}

using JwtLoginAp.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtLoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        public static readonly Dictionary<string, User> users = new();
        private readonly IConfiguration _configuration;
        
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult Register(UserDto request)
        {
            if(users.ContainsKey(request.Username))
            {
                return BadRequest("User already exists");
            }

            var passwordHash=BCrypt.Net.BCrypt.HashPassword(request.Password);
            var user = new User
            {
                Username = request.Username,
                PasswordHash = passwordHash,
            };
            users.Add(request.Username, user);
            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        public ActionResult Login(UserDto request)
        {
            if(!users.TryGetValue(request.Username, out User user))
            {
                return BadRequest("User not found");
            }

            if(!BCrypt.Net.BCrypt.Verify(request.Password,user.PasswordHash))
            {
                return BadRequest("Invalid password");
            }

            var token = CreateToken(user);
            return Ok(new { Token = token });

        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
               issuer: _configuration["Jwt:Issuer"],
               audience: _configuration["Jwt:Audience"],
               claims: claims,
               expires: DateTime.Now.AddMinutes(30),
               signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

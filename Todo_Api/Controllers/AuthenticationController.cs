using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Todo_Api.Data;
using Todo_Api.Authentication.SignUp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Todo_Api.Models;
using Todo_Api.DTOs;

namespace Todo_Api.Controllers
{
    [Route("Api/[controller]/[action]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IdentityDataContext _identityDataContext;
        private IConfiguration _configuration;

        public AuthenticationController(UserManager<AppUser> userManager,
                                        IdentityDataContext identityDataContext,
                                        IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
            _identityDataContext = identityDataContext;
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] UserLoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                    Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:DurationInMinutes"])),
                    Issuer = _configuration["Jwt:Issuer"],
                    Audience = _configuration["Jwt:Audience"],
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });
            }

            return Unauthorized();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> GetMe()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            var user = await _userManager.FindByIdAsync(userIdClaim.Value);

            if (user == null)
            {
                return NotFound("Kullanıcı Bulunamadı!");
            }

            return Ok(user);
        }

        [HttpPost]
        public async Task<IActionResult> Add([FromBody] UserRegisterDto model)
        {
            var userExist = await _userManager.FindByEmailAsync(model.Email);

            if (userExist != null)
            {
                return BadRequest("Kullanıcı Zaten Mevcut!");
            }

            Random random = new Random();
            
            AppUser user = new AppUser
            {
                UserName = model.Username,
                Email = model.Email,
                SecurityStamp = new Guid().ToString()
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok("Kullanıcı Başarıyla Oluşturuldu.");
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        private string ReplaceTurkishCharacters(string input)
        {
            string[] turkishChars = new string[] { "ç", "ğ", "ı", "ö", "ş", "ü", "Ç", "Ğ", "İ", "Ö", "Ş", "Ü" };
            string[] englishChars = new string[] { "c", "g", "i", "o", "s", "u", "C", "G", "I", "O", "S", "U" };

            for (int i = 0; i < turkishChars.Length; i++)
            {
                input = input.Replace(turkishChars[i], englishChars[i]);
            }

            return input;
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Update([FromBody] UserRegisterDto model)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            var user = await _userManager.FindByIdAsync(userIdClaim.Value);

            if (user == null)
            {
                return NotFound("Kullanıcı Bulunamadı!");
            }

            user.UserName = model.Username;
            user.Email = model.Email;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                return Ok(user);
            }

            return BadRequest("Kullanıcı Bilgileri Güncellenemedi!");
        }

        [HttpPost("{Id}")]
        public IActionResult Delete(int Id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            var model = _identityDataContext.Users.First(i => i.Id == Convert.ToInt32(userIdClaim.Value));

            if (model == null)
            {
                return NotFound("Kullanıcı Bulunamadı!");
            }

            var result = _identityDataContext.Users.Remove(model);
            _identityDataContext.SaveChanges();

            if (result != null)
            {
                return Ok("Kullanıcı Başarıyla Silindi.");
            }
            else
            {
                return BadRequest("Beklenmedik Bir Hata Tekrar Deneyiniz!");
            }
        }

        [HttpGet]
        public IActionResult DecodeToken([FromQuery] string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Token Bulunamadı!");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims = jwtToken.Claims.Select(c => new { c.Type, c.Value }).ToList();

                return Ok(claims);
            }
            catch
            {
                return Unauthorized();
            }
        }

        [HttpGet]
        [Authorize]
        public IActionResult ValidateToken()
        {
            return Ok(new { Message = "Token Geçerli." });
        }
    }
}

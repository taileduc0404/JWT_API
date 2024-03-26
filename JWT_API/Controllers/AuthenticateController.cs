
using JWT_API.DTOs;
using JWT_API.Models;
using JWT_API.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTRefreshToken.NET6._0.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            // Tìm kiếm người dùng trong hệ thống dựa trên tên người dùng (username) được cung cấp trong model
            var user = await _userManager.FindByNameAsync(model.Username!);
            // Kiểm tra xem người dùng có tồn tại và mật khẩu có khớp không
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password!))
            {
                // Lấy danh sách vai trò của người dùng
                var userRoles = await _userManager.GetRolesAsync(user);

                // Tạo danh sách các thông tin xác thực (claims) cho token JWT
                var authClaims = new List<Claim>
                {
                    // Thêm thông tin tên người dùng vào claims
                    new Claim(ClaimTypes.Name, user.UserName!),
                    // Thêm thông tin ID của token vào claims
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                // Duyệt qua danh sách các vai trò của người dùng và thêm vào claims
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                // Tạo token JWT từ các claims
                var token = CreateToken(authClaims);
                // Tạo refresh token mới
                var refreshToken = GenerateRefreshToken();

                // Lấy số ngày hợp lệ của refresh token từ cấu hình
                _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

                // Cập nhật refresh token và thời gian hết hạn của nó cho người dùng
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                // Cập nhật thông tin của người dùng vào cơ sở dữ liệu
                await _userManager.UpdateAsync(user);

                // Trả về thành công với token JWT, refresh token và thời gian hết hạn của token
                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo
                });
            }
            // Trả về lỗi 401 Unauthorized nếu thông tin đăng nhập không chính xác
            return Unauthorized();
        }



        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            // Kiểm tra xem người dùng có tồn tại trong hệ thống hay không dựa trên tên người dùng (username) được cung cấp trong model
            var userExists = await _userManager.FindByNameAsync(model.Username!);
            // Nếu người dùng tồn tại, trả về mã lỗi 500 và thông báo lỗi
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response_JWT { Status = "Error", Message = "User already exists!" });

            // Tạo một đối tượng người dùng mới
            ApplicationUser user = new()
            {
                Email = model.Email,
                // Tạo một security stamp ngẫu nhiên
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            // Tạo người dùng mới trong hệ thống sử dụng UserManager, với mật khẩu được cung cấp trong model
            var result = await _userManager.CreateAsync(user, model.Password!);
            // Nếu quá trình tạo người dùng không thành công, trả về mã lỗi 500 và thông báo lỗi
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response_JWT { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            // Nếu quá trình tạo người dùng thành công, trả về mã lỗi 200 và thông báo thành công
            return Ok(new Response_JWT { Status = "Success", Message = "User created successfully!" });
        }


        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register model)
        {
            // Kiểm tra xem người dùng có tồn tại trong hệ thống hay không dựa trên tên người dùng (username) được cung cấp trong model
            var userExists = await _userManager.FindByNameAsync(model.Username!);
            // Nếu người dùng tồn tại, trả về mã lỗi 500 và thông báo lỗi
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response_JWT { Status = "Error", Message = "User already exists!" });

            // Tạo một đối tượng người dùng mới
            ApplicationUser user = new()
            {
                Email = model.Email,
                // Tạo một security stamp ngẫu nhiên
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            // Tạo người dùng mới trong hệ thống sử dụng UserManager, với mật khẩu được cung cấp trong model
            var result = await _userManager.CreateAsync(user, model.Password!);
            // Nếu quá trình tạo người dùng không thành công, trả về mã lỗi 500 và thông báo lỗi
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response_JWT { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            // Tạo vai trò quản trị viên nếu nó chưa tồn tại
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            // Tạo vai trò người dùng nếu nó chưa tồn tại
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            // Thêm vai trò quản trị viên cho người dùng mới
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            // Thêm vai trò người dùng cho người dùng mới
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }

            // Trả về mã lỗi 200 và thông báo thành công
            return Ok(new Response_JWT { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(Token tokenModel)
        {
            // Kiểm tra xem tokenModel có null không
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            // Lấy accessToken và refreshToken từ tokenModel
            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            // Lấy principal từ accessToken
            var principal = GetPrincipalFromExpiredToken(accessToken);
            // Kiểm tra xem principal có null không
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            // Lấy username từ principal
            #pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            #pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Identity.Name;
            #pragma warning restore CS8602 // Dereference of a possibly null reference.
            #pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            // Tìm người dùng trong hệ thống dựa trên username
            var user = await _userManager.FindByNameAsync(username!);

            // Kiểm tra tính hợp lệ của refreshToken và thời gian hết hạn của nó
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            // Tạo accessToken mới và refreshToken mới
            var newAccessToken = CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();

            // Cập nhật refreshToken mới cho người dùng trong cơ sở dữ liệu
            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            // Trả về mã lỗi 200 và accessToken mới và refreshToken mới
            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }


        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            // Tìm người dùng trong hệ thống dựa trên tên người dùng được cung cấp
            var user = await _userManager.FindByNameAsync(username);
            // Kiểm tra xem người dùng có tồn tại không
            if (user == null) return BadRequest("Invalid user name");

            // Đặt giá trị của refreshToken của người dùng thành null
            user.RefreshToken = null;
            // Cập nhật thông tin người dùng vào cơ sở dữ liệu
            await _userManager.UpdateAsync(user);

            // Trả về mã lỗi 204 No Content để chỉ ra rằng hoạt động đã thành công
            return NoContent();
        }


        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            // Lấy danh sách tất cả người dùng trong hệ thống
            var users = _userManager.Users.ToList();
            // Duyệt qua từng người dùng trong danh sách
            foreach (var user in users)
            {
                // Đặt giá trị của refreshToken của người dùng thành null
                user.RefreshToken = null;
                // Cập nhật thông tin người dùng vào cơ sở dữ liệu
                await _userManager.UpdateAsync(user);
            }

            // Trả về mã lỗi 204 No Content để chỉ ra rằng hoạt động đã thành công
            return NoContent();
        }


        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            // Tạo một khóa đối xứng từ chuỗi bí mật được lấy từ cấu hình
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            // Lấy thời gian hợp lệ của token từ cấu hình và chuyển đổi nó thành số nguyên
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            // Tạo một đối tượng JwtSecurityToken
            var token = new JwtSecurityToken(
                // Thiết lập issuer cho token
                issuer: _configuration["JWT:ValidIssuer"],
                // Thiết lập audience cho token
                audience: _configuration["JWT:ValidAudience"],
                // Thiết lập thời gian hết hạn của token (tính từ thời điểm hiện tại)
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                // Thiết lập các thông tin xác thực (claims) cho token
                claims: authClaims,
                // Thiết lập phương thức ký cho token bằng cách sử dụng khóa đối xứng được tạo trước đó
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            // Trả về đối tượng JwtSecurityToken đã tạo
            return token;
        }


        private static string GenerateRefreshToken()
        {
            // Tạo một mảng byte có độ dài 64 byte để chứa số ngẫu nhiên
            var randomNumber = new byte[64];
            // Sử dụng lớp RandomNumberGenerator để tạo số ngẫu nhiên
            using var rng = RandomNumberGenerator.Create();
            // Lấy các byte ngẫu nhiên và lưu vào mảng byte đã tạo
            rng.GetBytes(randomNumber);
            // Chuyển đổi mảng byte thành một chuỗi base64 và trả về
            return Convert.ToBase64String(randomNumber);
        }


        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            // Thiết lập các thông số để xác thực token, trong trường hợp này, chúng ta không kiểm tra audience, issuer và thời gian sống của token
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                // Sử dụng khóa đối xứng từ chuỗi bí mật trong cấu hình để xác thực chữ ký của token
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!)),
                // Bỏ qua kiểm tra thời gian sống của token, do token đã hết hạn
                ValidateLifetime = false
            };

            // Tạo một đối tượng JwtSecurityTokenHandler để xử lý token
            var tokenHandler = new JwtSecurityTokenHandler();
            // Xác thực token sử dụng các thông số được thiết lập trước đó và trả về principal của token
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            // Kiểm tra xem token có thuộc loại JwtSecurityToken và thuật toán ký của nó có phải là HmacSha256 không
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                // Nếu không, ném ra một ngoại lệ SecurityTokenException với thông báo lỗi
                throw new SecurityTokenException("Invalid token");

            // Trả về principal của token
            return principal;
        }

    }
}
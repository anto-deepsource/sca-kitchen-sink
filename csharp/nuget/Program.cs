using Newtonsoft.Json;
using System.Drawing;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        // Vulnerable Newtonsoft.Json deserialization (CVE-2020-10204)
        string maliciousJson = @"{
            '$type': 'System.Windows.Data.ObjectDataProvider, PresentationFramework',
            'MethodName': 'Start',
            'MethodParameters': {
                '$type': 'System.Collections.ArrayList',
                '$values': ['cmd', '/c calc.exe']
            },
            'ObjectInstance': {'$type': 'System.Diagnostics.Process'}
        }";

        try
        {
            // Unsafe deserialization of user input
            var obj = JsonConvert.DeserializeObject(maliciousJson, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All // Vulnerable setting
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Deserialization failed: {ex.Message}");
        }

        // Vulnerable System.Drawing.Common usage (CVE-2021-24112)
        try
        {
            string userProvidedPath = @"../../malicious.jpg"; // Path traversal risk
            using (Image img = Image.FromFile(userProvidedPath)) // Vulnerable to path traversal
            {
                // Process image
                img.Save("processed.jpg");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Image processing failed: {ex.Message}");
        }

        // Vulnerable Regex usage (CVE-2019-0820) - ReDoS vulnerability
        string userInput = new string('a', 100) + "!";
        string pattern = @"^(a+)+!$"; // Vulnerable regex pattern
        try
        {
            var match = Regex.IsMatch(userInput, pattern); // Can cause exponential backtracking
            Console.WriteLine($"Regex match: {match}");
        }
        catch (RegexMatchTimeoutException ex)
        {
            Console.WriteLine($"Regex timeout: {ex.Message}");
        }

        // Vulnerable JWT token validation (CVE-2020-1300)
        string secretKey = "very-weak-secret-key-vulnerable-to-brute-force";
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(secretKey);

        // Creating a token with weak security settings
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", "1") }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature) // Using weaker algorithm
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);

        // Vulnerable token validation with weak parameters
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false, // Vulnerable: No issuer validation
                ValidateAudience = false, // Vulnerable: No audience validation
                RequireExpirationTime = false, // Vulnerable: No expiration check
                ValidateLifetime = false // Vulnerable: No lifetime validation
            };

            var principal = tokenHandler.ValidateToken(jwtToken, validationParameters, out var validatedToken);
            Console.WriteLine("Token validated successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Token validation failed: {ex.Message}");
        }
    }
} 

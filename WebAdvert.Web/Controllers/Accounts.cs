using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool cognitoUserPool;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool cognitoUserPool)
        {
            this.signInManager = signInManager;
            this._userManager = userManager;
            this.cognitoUserPool = cognitoUserPool;
        }

        public IActionResult Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = cognitoUserPool.GetUser(model.Email);
                if(user == null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exist");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded)
                {
                    return Redirect("/Accounts/Confirm");
                }
                else
                {
                    foreach (var item in createdUser.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                }

            }
            return View(model);
        }

        public IActionResult Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found");
                    return View(model);
                }

                var result = await ((CognitoUserManager<CognitoUser>)_userManager).ConfirmSignUpAsync(user, model.Code, true);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                }
            }

            return View(model);
        }


        public IActionResult Login()
        {
            var model = new LoginModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("InvalidCredentials", "The username or password is incorrect");
                return View(model);
            }

            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.Rememberme, false);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("LoginError", "Email or password do not match");
            }


            return View(model);

        }

        public async Task<IActionResult> Signout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Login", "Accounts");
        }


        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return RedirectToAction("Resetpassword", "Accounts");
            }

            // Cognito will send notification to user with reset token the user can use to reset their password.
            await user.ForgotPasswordAsync();

                return RedirectToAction("Resetpassword", "Accounts");

        }

        public IActionResult Resetpassword()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> Resetpassword(ResetPasswordModel model)
        {

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                throw new InvalidOperationException($"Unable to retrieve user.");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

            if (result.Succeeded)
            {
                return RedirectToAction("Login", "Accounts");
            }
            else
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                }
            }

            return View(model);
        }


    }
}

﻿using System.ComponentModel.DataAnnotations;

namespace WebAdvert.Web.Models.Accounts
{
    public class ResetPasswordModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Code is required")]
        public string Code { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(12, ErrorMessage = "Password must be at least six characters long")]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and its confirmation do not match")]
        public string ConfirmPassword { get; set; }
    }
}
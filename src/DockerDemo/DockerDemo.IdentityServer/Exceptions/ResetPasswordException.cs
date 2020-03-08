using System;

namespace DockerDemo.IdentityServer.Exceptions
{
    public class ResetPasswordException: Exception
    {
        public ResetPasswordException(string errors) : base(errors)
        {
        }
    }
}
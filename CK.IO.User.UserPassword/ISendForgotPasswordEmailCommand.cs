using CK.Core;
using CK.Cris;

namespace CK.IO.User.UserPassword;

public interface ISendForgotPasswordEmailCommand : ICommand<SimpleUserMessage>, ICommandCurrentCulture
{
    public string Email { get; set; }
}

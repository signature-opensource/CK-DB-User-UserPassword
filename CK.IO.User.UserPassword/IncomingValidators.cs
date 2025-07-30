using CK.Core;
using CK.Cris;

namespace CK.IO.User.UserPassword;

public class IncomingValidators : IRealObject
{
    [IncomingValidator]
    public virtual void ValidateSetPasswordCommand( UserMessageCollector collector, ISetPasswordCommand command )
    {
        if( command.UserId <= 0 )
        {
            collector.Error( "Invalid UserId.", "User.InvalidUserId" );
        }

        if( string.IsNullOrWhiteSpace( command.Password ) )
        {
            collector.Error( "Invalid password.", "User.InvalidPassword" );
        }

        if( command.ActorId.GetValueOrDefault() != command.UserId )
        {
            collector.Error( "ActorId must match UserId.", "User.ActorAndUserMustMatch" );
        }
    }

    [IncomingValidator]
    public virtual void ValidateCreateOrUpdateCommand( UserMessageCollector collector, ICreateOrUpdatePasswordCommand command )
    {
        if( command.UserId <= 0 )
        {
            collector.Error( "Invalid UserId.", "User.InvalidUserId" );
        }

        if( string.IsNullOrWhiteSpace( command.Password ) )
        {
            collector.Error( "Invalid password.", "User.InvalidPassword" );
        }
    }
}

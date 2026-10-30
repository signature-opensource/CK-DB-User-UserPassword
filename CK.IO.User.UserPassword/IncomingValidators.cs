using CK.Core;
using CK.Cris;
using System;

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
    public virtual void ValidateAddPasswordCommand( UserMessageCollector collector, IAddPasswordCommand command )
    {
        if( string.IsNullOrWhiteSpace( command.Password ) )
        {
            collector.Error( "Invalid password.", "User.InvalidPassword" );
        }
        if( command.ActorId != command.ActualActorId )
        {
            collector.Error( "This is refused while impersonating.", "Authentication.Impersonated" );
        }
    }

    [IncomingValidator]
    public virtual void ValidateRemovePasswordCommand( UserMessageCollector collector, IRemovePasswordCommand command )
    {
        if( command.ActorId != command.ActualActorId )
        {
            collector.Error( "This is refused while impersonating.", "Authentication.Impersonated" );
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

        if( !Enum.IsDefined( command.CreationMode ) )
        {
            collector.Error( "Invalid CreationMode.", "User.InvalidCreationMode" );
        }
    }
}

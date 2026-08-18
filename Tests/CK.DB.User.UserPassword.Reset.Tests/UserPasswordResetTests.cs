using CK.Core;
using CK.Cris;
using CK.DB.Auth;
using CK.IO.Actor;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Reset.Tests;

[TestFixture]
public class UserPasswordResetTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor.
    AsyncServiceScope _scope;
    IServiceProvider _services;
    CrisExecutionContext _executor;
    PocoDirectory _pocoDir;
    Actor.UserTable _userTable;
    UserPasswordResetTable _table;
    UserPasswordTable _pwdTable;
#pragma warning restore CS8618

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _scope = SharedEngine.AutomaticServices.CreateAsyncScope();
        _services = _scope.ServiceProvider;

        _pocoDir = _services.GetRequiredService<PocoDirectory>();
        _executor = _services.GetRequiredService<CrisExecutionContext>();

        _userTable = _services.GetRequiredService<Actor.UserTable>();
        _table = _services.GetRequiredService<UserPasswordResetTable>();
        _pwdTable = _services.GetRequiredService<UserPasswordTable>();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        await _scope.DisposeAsync();
    }

    [Test]
    public async Task setting_a_temporary_password_flags_the_user_profile_Async()
    {
        var (userId, _) = await CreatePasswordUserAsync( "temp-flagged" );

        await SetPasswordAsync( userId, "Temp$Pwd1", isTemporary: true );

        var profile = await ReadProfileAsync( userId );
        profile.IsTemporaryPassword.ShouldBeTrue( "The password has been set as temporary." );
    }

    [Test]
    public async Task setting_a_password_without_the_flag_clears_the_temporary_state_Async()
    {
        var (userId, _) = await CreatePasswordUserAsync( "temp-cleared" );

        await SetPasswordAsync( userId, "Temp$Pwd1", isTemporary: true );
        (await ReadProfileAsync( userId )).IsTemporaryPassword.ShouldBeTrue();

        // IsTemporary defaults to false: the user chose its own password.
        await SetPasswordAsync( userId, "Chosen$Pwd1" );

        var profile = await ReadProfileAsync( userId );
        profile.IsTemporaryPassword.ShouldBeFalse( "Setting a password without the flag clears the temporary state." );
    }

    [Test]
    public async Task logging_in_with_the_temporary_password_does_not_clear_the_flag_Async()
    {
        var (userId, _) = await CreatePasswordUserAsync( "temp-kept-on-login" );

        const string pwd = "Temp$Pwd1";
        await SetPasswordAsync( userId, pwd, isTemporary: true );

        using( var ctx = new SqlStandardCallContext() )
        {
            var loginRes = await _pwdTable.LoginUserAsync( ctx, userId, pwd );
            loginRes.IsSuccess.ShouldBeTrue( "Login must succeed with the temporary password." );
        }

        var profile = await ReadProfileAsync( userId );
        profile.IsTemporaryPassword.ShouldBeTrue( "An actual login must not clear the temporary flag." );
    }

    [Test]
    public async Task a_user_without_any_password_is_not_flagged_Async()
    {
        // No CK.tUserPassword row at all: the left outer join yields null, isnull() maps it to false.
        int userId;
        using( var ctx = new SqlStandardCallContext() )
        {
            userId = await _userTable.CreateUserAsync( ctx, 1, Guid.NewGuid().ToString() );
        }

        var profile = await ReadProfileAsync( userId );
        profile.IsTemporaryPassword.ShouldBeFalse( "A user with no password registration is not flagged." );
    }

    [Test]
    public async Task creating_a_password_with_the_flag_sets_it_right_away_Async()
    {
        // Exercises the PostCreate injection: the flag is written by the creation pass itself.
        int userId;
        using( var ctx = new SqlStandardCallContext() )
        {
            userId = await _userTable.CreateUserAsync( ctx, 1, Guid.NewGuid().ToString() );
            var r = await _table.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, "Initial$Pwd1", UCLMode.CreateOnly, isTemporary: true );
            r.OperationResult.ShouldBe( UCResult.Created );
        }

        var profile = await ReadProfileAsync( userId );
        profile.IsTemporaryPassword.ShouldBeTrue( "The created password has been flagged as temporary." );
    }

    async Task<(int UserId, string UserName)> CreatePasswordUserAsync( string prefix )
    {
        var userName = $"{prefix}-{Guid.NewGuid()}";
        using( var ctx = new SqlStandardCallContext() )
        {
            var userId = await _userTable.CreateUserAsync( ctx, 1, userName );
            userId.ShouldBeGreaterThan( 0 );
            await _pwdTable.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, "Initial$Pwd1", UCLMode.CreateOnly );
            return (userId, userName);
        }
    }

    async Task SetPasswordAsync( int userId, string password, bool? isTemporary = null )
    {
        var cmd = _pocoDir.Create<IO.User.UserPassword.Reset.ISetPasswordCommand>( c =>
        {
            c.ActorId = userId;
            c.UserId = userId;
            c.Password = password;
            if( isTemporary.HasValue ) c.IsTemporary = isTemporary.Value;
        } );
        var executingCmd = await _executor.ExecuteRootCommandAsync( cmd );
        var res = executingCmd.WithResult<ICrisBasicCommandResult>().Result;
        res.ShouldNotBeNull();
        res.Success.ShouldBeTrue( $"SetPassword must succeed: {string.Join( ", ", res.UserMessages )}" );
    }

    async Task<IO.User.UserPassword.Reset.IUserProfile> ReadProfileAsync( int userId )
    {
        var cmd = _pocoDir.Create<IGetUserProfileQCommand>( c =>
        {
            c.ActorId = userId;
            c.UserId = userId;
        } );
        var executingCmd = await _executor.ExecuteRootCommandAsync( cmd );
        var profile = executingCmd.WithResult<IUserProfile?>().Result;
        profile.ShouldNotBeNull();
        TestHelper.Monitor.Info( $"Profile read. (UserId: {profile.UserId}, UserName: {profile.UserName})" );
        return (IO.User.UserPassword.Reset.IUserProfile)profile;
    }
}

using CK.Core;
using CK.DB.Actor;
using CK.DB.Actor.ActorEMail;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using Shouldly;
using NUnit.Framework;
using System;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.EMailLogin.Tests;

[TestFixture]
public class EMailLoginTests
{
    [Test]
    public void login_by_validated_email_succeeds_and_user_name_still_works()
    {
        var pwd = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        var emails = SharedEngine.Map.StObjs.Obtain<ActorEMailTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            var userName = Guid.NewGuid().ToString();
            var email = $"{Guid.NewGuid():N}@test.com";
            var password = "S3cr3t!";
            int userId = user.CreateUser( ctx, 1, userName );

            pwd.CreateOrUpdatePasswordUser( ctx, 1, userId, password ).OperationResult.ShouldBe( UCResult.Created );
            emails.AddEMail( ctx, 1, userId, email, isPrimary: true, validate: true );

            // Login by validated email resolves to the user.
            pwd.LoginUser( ctx, email, password ).UserId.ShouldBe( userId );
            // Login by user name keeps working (non-regression).
            pwd.LoginUser( ctx, userName, password ).UserId.ShouldBe( userId );
            // Wrong password by email fails.
            pwd.LoginUser( ctx, email, "wrong" ).IsSuccess.ShouldBeFalse();

            user.DestroyUser( ctx, 1, userId );
        }
    }

    [Test]
    public void login_by_unvalidated_email_fails()
    {
        var pwd = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        var emails = SharedEngine.Map.StObjs.Obtain<ActorEMailTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            var userName = Guid.NewGuid().ToString();
            var email = $"{Guid.NewGuid():N}@test.com";
            var password = "S3cr3t!";
            int userId = user.CreateUser( ctx, 1, userName );

            pwd.CreateOrUpdatePasswordUser( ctx, 1, userId, password );
            // Email added but NOT validated.
            emails.AddEMail( ctx, 1, userId, email, isPrimary: true, validate: false );

            // Login by an unvalidated email is refused (unknown login key).
            pwd.LoginUser( ctx, email, password ).IsSuccess.ShouldBeFalse();
            // The user name still logs in.
            pwd.LoginUser( ctx, userName, password ).UserId.ShouldBe( userId );

            user.DestroyUser( ctx, 1, userId );
        }
    }

    [Test]
    public void login_by_validated_but_non_primary_email_fails()
    {
        var pwd = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        var emails = SharedEngine.Map.StObjs.Obtain<ActorEMailTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            var userName = Guid.NewGuid().ToString();
            var primaryEmail = $"{Guid.NewGuid():N}@test.com";
            var secondaryEmail = $"{Guid.NewGuid():N}@test.com";
            var password = "S3cr3t!";
            int userId = user.CreateUser( ctx, 1, userName );

            pwd.CreateOrUpdatePasswordUser( ctx, 1, userId, password );
            // A validated primary email and a validated secondary (non-primary) email.
            emails.AddEMail( ctx, 1, userId, primaryEmail, isPrimary: true, validate: true );
            emails.AddEMail( ctx, 1, userId, secondaryEmail, isPrimary: false, validate: true );

            // Only the primary email logs in.
            pwd.LoginUser( ctx, primaryEmail, password ).UserId.ShouldBe( userId );
            // The validated but non-primary email is refused.
            pwd.LoginUser( ctx, secondaryEmail, password ).IsSuccess.ShouldBeFalse();

            user.DestroyUser( ctx, 1, userId );
        }
    }
}

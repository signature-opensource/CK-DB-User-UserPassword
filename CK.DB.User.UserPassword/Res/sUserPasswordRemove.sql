-- SetupConfig: { "Requires": [ "CK.fAuthUserHasOtherScheme" ] }
--
-- The actor removes its own password.
-- @Result: 0 = NotFound (no password), 1 = Removed, 2 = LastLoginMethod (refused).
--
-- The "last login method" rule applies (CK.DB.Auth): the password is not removed when the actor has no other scheme in
-- CK.vUserAuthProvider.
--
create procedure CK.sUserPasswordRemove
(
	@ActorId int,
	@Result int output
)
as
begin
    if @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;

	--[beginsp]

	-- Locks the password of the actor: a concurrent removal of its other login methods is serialized by their own lock.
	set @Result = 0;
	if exists( select 1 from CK.tUserPassword with(updlock, holdlock) where UserId = @ActorId )
	begin
		if CK.fAuthUserHasOtherScheme( @ActorId, 'Basic' ) = 0
		begin
			set @Result = 2;
		end
		else
		begin
			--<PreRemove revert />
			delete CK.tUserPassword where UserId = @ActorId;
			set @Result = 1;
			--<PostRemove />
		end
	end

	--[endsp]
end

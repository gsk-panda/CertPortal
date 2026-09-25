-- Set-password tokens now serve two purposes: password resets and new-user invites
ALTER TABLE password_reset_tokens
  ADD COLUMN purpose text NOT NULL DEFAULT 'reset' CHECK (purpose IN ('reset','invite'));

-- Permanent free tier replaces the time-limited trial for self-serve signups.
-- Orgs still on 'trial' move to 'free' so they are never locked out when the
-- trial window passes; paid and grandfathered orgs are untouched.
UPDATE organizations SET plan = 'free', trial_ends_at = NULL WHERE plan = 'trial';

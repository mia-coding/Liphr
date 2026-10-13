import { createClient } from '@supabase/supabase-js'

// The anon key is designed to be public. Row Level Security (see supabase/schema.sql)
// is what actually protects each user's data.
export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
)

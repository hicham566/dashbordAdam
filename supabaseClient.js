
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm'

// TODO: User to replace these with their own project details from supabase.com
const SUPABASE_URL = 'https://ziysrqhppmibfgqyyrqx.supabase.co'
const SUPABASE_KEY = 'sb_publishable_3LeWsGoWPMHlrX7SK-_x2Q_Ao5IgOyy'

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)

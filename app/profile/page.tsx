import { createClient } from '@/utils/supabase/server'
import { redirect } from 'next/navigation'

export default async function ProfilePage() {
  const supabase = await createClient()

  const { data: { session } } = await supabase.auth.getSession()
  
  if (!session) {
    redirect('/login')
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', session.user.id)
    .single()

  return (
    <div className="w-full max-w-4xl mx-auto mt-12 px-4">
      <h1 className="text-2xl font-bold mb-4">프로필</h1>
      <div className="bg-white rounded-xl shadow-lg p-6">
        <p>이메일: {profile?.email}</p>
        <p>이름: {profile?.name || '미설정'}</p>
      </div>
    </div>
  )
} 
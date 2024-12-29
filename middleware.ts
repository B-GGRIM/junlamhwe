import { createMiddlewareClient } from '@supabase/auth-helpers-nextjs'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export async function middleware(req: NextRequest) {
  const res = NextResponse.next()
  const supabase = createMiddlewareClient({ req, res })

  const {
    data: { session },
  } = await supabase.auth.getSession()

  // 로그인이 필요한 페이지들
  const protectedRoutes = ['/dashboard']
  
  // 현재 접근하려는 경로
  const path = req.nextUrl.pathname

  // 로그인이 필요한 페이지인데 로그인이 되어있지 않은 경우
  if (protectedRoutes.includes(path) && !session) {
    return NextResponse.redirect(new URL('/', req.url))
  }

  // 이미 로그인된 상태에서 시작 페이지로 접근하는 경우
  if (path === '/' && session) {
    return NextResponse.redirect(new URL('/dashboard', req.url))
  }

  return res
}

// 미들웨어가 실행될 경로 설정
export const config = {
  matcher: ['/', '/dashboard', '/dashboard/:path*']
}
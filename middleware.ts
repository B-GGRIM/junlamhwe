import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const isLoggedIn = request.cookies.get('isLoggedIn')

  // 로그인된 사용자가 루트 경로('/')에 접근하는 경우
  if (request.nextUrl.pathname === '/' && isLoggedIn) {
    return NextResponse.redirect(new URL('/home', request.url))
  }

  // /home 경로에 대한 기존 로직
  if (request.nextUrl.pathname.startsWith('/home')) {
    if (!isLoggedIn) {
      return NextResponse.redirect(new URL('/', request.url))
    }
  }
  
  return NextResponse.next()
}

export const config = {
  // 루트 경로도 미들웨어가 처리하도록 매처 수정
  matcher: ['/', '/home/:path*']
}
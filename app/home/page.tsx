'use client'

import { useEffect, useState } from 'react'
import Header from '@/app/components/Header/Header'
import Footer from '@/app/components/Footer/Footer';

export default function TestPage() {
  const [userData, setUserData] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    // 로그인 체크
    const isLoggedIn = sessionStorage.getItem('isLoggedIn')
    const userDataStr = sessionStorage.getItem('userData')

    if (!isLoggedIn || !userDataStr) {
      document.location.href = '/'
      return
    }

    setUserData(JSON.parse(userDataStr))
    setIsLoading(false)
  }, [])

  const handleLogout = () => {
    // 세션스토리지에서 로그인 정보 삭제
    sessionStorage.removeItem('isLoggedIn')
    sessionStorage.removeItem('userData')
    
    // 홈으로 리다이렉트
    document.location.href = '/'
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col">
        <Header />
        <div className="flex-1 p-8 flex items-center justify-center">
          <div className="animate-pulse text-gray-500">로딩중...</div>
        </div>
        <Footer />
      </div>
    )
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <div className="flex-1 p-8">
        <h1 className="text-2xl font-bold mb-4">테스트 페이지</h1>
        <p className="mb-4">로그인 성공! {userData.name}님 환영합니다!</p>
        
        <button
          onClick={handleLogout}
          className="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded"
        >
          로그아웃
        </button>
      </div>
      <Footer />
    </div>
  )
}
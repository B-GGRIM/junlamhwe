'use client'

import { useState, useEffect } from 'react'
import Header from '../components/Header/Header'
import Footer from '@/app/components/Footer/Footer';
import { useRouter } from 'next/navigation'

export default function TestPage() {
  const [userData, setUserData] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const isLoggedIn = sessionStorage.getItem('isLoggedIn')
    const userDataStr = sessionStorage.getItem('userData')

    if (!isLoggedIn || !userDataStr) {
      document.location.href = '/'
      return
    }

    try {
      const parsedUserData = JSON.parse(userDataStr)
      setUserData(parsedUserData)
    } catch (error) {
      console.error('Failed to parse user data:', error)
      document.location.href = '/'
      return
    }
    
    setIsLoading(false)
  }, [])

  const handleLogout = () => {
    document.cookie = 'isLoggedIn=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT'
    sessionStorage.clear()
    router.push('/')
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <div className="flex-1 p-8">
        <h1 className="text-2xl font-bold mb-4">테스트 페이지</h1>
        {!isLoading && userData && (
          <p className="mb-4">로그인 성공! {userData.name}님 환영합니다!</p>
        )}
        
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
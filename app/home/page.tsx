'use client'

import { useState, useEffect } from 'react'
import Header from '../components/Header/Header'
import Footer from '@/app/components/Footer/Footer';
import { useRouter } from 'next/navigation'
import MealSection from '../components/MealSection/MealSection'

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
      <div className="relative w-full h-[75vh]">
        {/* Background Image */}
        <div 
          className="absolute inset-0 bg-cover bg-center -z-10" 
          style={{ backgroundImage: 'url("/background01.jpg")' }}
        ></div>

        {/* Noise overlay */}
        <div 
          className="absolute inset-0 opacity-[0.25] mix-blend-soft-light z-0"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")`,
            backgroundSize: '200px 200px'
          }}
        ></div>

        {/* Overlay for depth */}
        <div className="absolute inset-0 bg-gradient-to-br from-transparent via-black/10 to-black/20 z-0"></div>
      </div>
      
      {/* Meal Section */}
      <section className="bg-white py-28">
            <div className="max-w-6xl mx-auto px-4">
              <div className="flex items-center pr-5 pl-5 pb-2 mt-5">
                <h2 className="text-xl font-bold">
                  {new Date().toLocaleDateString('ko-KR', { year: 'numeric', month: 'long', day: 'numeric' })}
                </h2>
                <button 
                  className="text-gray-600 bg-gray-100 hover:bg-gray-200 text-xs font-medium transition-colors ml-3 px-2.5 py-1 rounded-full"
                  onClick={() => {/* 더보기 기능 추가 */}}
                >
                  더보기
                </button>
              </div>
              <div className="flex flex-col">
                <MealSection />
              </div>
            </div>
          </section>
      
      <Footer />
    </div>
  )
}
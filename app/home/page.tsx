'use client'

import { useState, useEffect } from 'react'
import Header from '../components/Header/Header'
import Footer from '@/app/components/Footer/Footer';
import { useRouter } from 'next/navigation'
import MealSection from '../components/MealSection/MealSection'
import { createClientComponentClient } from '@supabase/auth-helpers-nextjs'

export default function TestPage() {
  const [userData, setUserData] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [specialRoomRequests, setSpecialRoomRequests] = useState<any[]>([])
  const supabase = createClientComponentClient()
  const router = useRouter()

  const teachers_data = [
    { id: 1, name: "김민철", subject: "수학" },
    { id: 2, name: "고경석", subject: "물리" },
    { id: 3, name: "김태경", subject: "물리" },
    { id: 4, name: "양은심", subject: "정보" },
    { id: 5, name: "유지호", subject: "역사" },
    { id: 6, name: "이경진", subject: "국어" },
    { id: 7, name: "최정호", subject: "수학" },
    { id: 8, name: "현지수", subject: "국어" },
    { id: 9, name: "박주희", subject: "" },
    { id: 10, name: "이윤우", subject: "" },
    { id: 11, name: "박강희", subject: "" },
    { id: 12, name: "오동율", subject: "수학" },
    { id: 13, name: "최바울", subject: "생명" },
    { id: 14, name: "김진욱", subject: "체육" },
    { id: 15, name: "양원", subject: "국어" },
    { id: 16, name: "한승진", subject: "화학" },
    { id: 17, name: "이경숙", subject: "보건" },
    { id: 18, name: "정지용", subject: "수학" },
    { id: 19, name: "문지섭", subject: "생명" },
    { id: 20, name: "차민서", subject: "화학" },
    { id: 21, name: "강지연", subject: "영어" },
    { id: 22, name: "강신혜", subject: "정보" },
    { id: 23, name: "양동애", subject: "" },
    { id: 24, name: "조현태", subject: "지구" },
    { id: 25, name: "최원태", subject: "지구" }
  ];

  console.log(teachers_data[0].name); // "김민철" 출력

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
    
    // 특별실 신청 데이터 가져오기
    const fetchSpecialRoomRequests = async () => {
      try {
        const { data, error } = await supabase
          .from('special_room_requests')
          .select('*')
          .order('created_at', { ascending: false })

        if (error) throw error
        setSpecialRoomRequests(data || [])
      } catch (error) {
        console.error('특별실 신청 데이터 조회 실패:', error)
      }
    }

    fetchSpecialRoomRequests()
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

        {/* Special Room Requests Table */}
        <div className="relative z-10 max-w-6xl mx-auto px-4 pt-10">
          <div className="p-6">
            <div className="flex items-center pb-4">
              <h2 className="text-xl font-bold text-gray-100">특별실 신청 현황</h2>
              <button 
              className="text-gray-600 bg-gray-100 hover:bg-gray-200 text-xs font-medium transition-colors ml-3 px-2.5 py-1 rounded-full"
                onClick={() => router.push('/home/specialroom')}
              >
                신청하기
              </button>
            </div>
            
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-800">
                <thead className="bg-gray-200/90">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">시간</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">장소</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">목적</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">담당교사</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">상태</th>
                  </tr>
                </thead>
                <tbody className="bg-gray-800/30 divide-y divide-gray-800">
                  {specialRoomRequests.map((request, index) => (
                    <tr key={index} className="hover:bg-gray-800/50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-semibold">{request.time}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-semibold">{request.location}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-semibold">{request.purpose}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-semibold">{teachers_data[request.teacher-1].name}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                          ${request.status === 'pending' ? 'bg-yellow-900/60 text-yellow-200' : 
                            request.status === 'approved' ? 'bg-green-900/60 text-green-200' : 
                            'bg-red-900/60 text-red-200'}`}>
                          {request.status === 'pending' ? '대기중' : 
                           request.status === 'approved' ? '승인됨' : '거절됨'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
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
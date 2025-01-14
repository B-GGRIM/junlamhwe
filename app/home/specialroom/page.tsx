"use client"

import Header from "@/app/components/Header/Header";
import { useState } from "react";
import TimeSelection from "@/app/components/TimeSelection/TimeSelection";
import LocationSelection from "@/app/components/LocationSelection/LocationSelection";
import PurposeSelection from "@/app/components/PurposeSelection/PurposeSelection";
import StudentSelection from "@/app/components/StudentSelection/StudentSelection";
import TeacherSelection from "@/app/components/TeacherSelection/TeacherSelection";
import Footer from "@/app/components/Footer/Footer";
import { createClientComponentClient } from '@supabase/auth-helpers-nextjs'
import { useRouter } from 'next/navigation'

export default function SpecialRoom() {
  const supabase = createClientComponentClient()
  const router = useRouter()
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    time: "",
    location: "",
    purpose: "",
    students: [],
    teacher: "",
  });

  const renderStep = () => {
    switch (step) {
      case 1:
        return <TimeSelection 
          formData={formData} 
          setFormData={setFormData}
          onNext={() => setStep(step + 1)} 
        />;
      case 2:
        return <LocationSelection 
          formData={formData} 
          setFormData={setFormData}
          onNext={() => setStep(step + 1)}
          onBack={() => setStep(step - 1)}
        />;
      case 3:
        return <PurposeSelection 
          formData={formData} 
          setFormData={setFormData}
          onNext={() => setStep(step + 1)}
          onBack={() => setStep(step - 1)}
        />;
      case 4:
        return <StudentSelection 
          formData={formData} 
          setFormData={setFormData}
          onNext={() => setStep(step + 1)}
          onBack={() => setStep(step - 1)}
        />;
      case 5:
        return <TeacherSelection 
          formData={formData} 
          setFormData={setFormData}
          onSubmit={handleSubmit}
          onBack={() => setStep(step - 1)}
        />;
      default:
        return null;
    }
  };

  const handleSubmit = async () => {
    // Supabase로 전송될 데이터 로깅
    console.log('특별실 신청 데이터:', {
      time: formData.time,
      location: formData.location,
      purpose: formData.purpose,
      students: formData.students,
      teacher: formData.teacher,
      status: 'pending'
    });

    try {
      const { data, error } = await supabase
        .from('special_room_requests')
        .insert([
          {
            time: formData.time,
            location: formData.location,
            purpose: formData.purpose,
            students: formData.students,
            teacher: formData.teacher,
            status: 'pending'
          }
        ])
        .select()

      if (error) {
        throw error
      }

      // 성공 시 응답 데이터도 로깅
      console.log('저장된 데이터:', data)
      alert('특별실 신청이 완료되었습니다.')
      router.push('/home')
      
    } catch (error) {
      console.error('Error inserting data:', error)
      alert('신청 중 오류가 발생했습니다. 다시 시도해주세요.')
    }
  }

  return (
    <div className="min-h-screen bg-white">
      <Header />
      <div className="max-w-2xl mx-auto p-6 mt-8 mb-10">
        <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-3">특별실 신청</h1>
          <div className="relative mb-8">
            <div className="absolute top-1/2 left-0 right-0 h-1 bg-gray-100 -translate-y-1/2 z-0" />
            <div 
              className="absolute top-1/2 left-0 h-1 bg-[#3ECF8E] transition-all duration-300 -translate-y-1/2 z-0"
              style={{ width: `${((step - 1) / 4) * 100}%` }}
            />
            <div className="relative flex justify-between z-10">
              {[1, 2, 3, 4, 5].map((num) => (
                <div
                  key={num}
                  className={`
                    w-8 h-8 rounded-full flex items-center justify-center text-sm
                    transition-all duration-300 relative
                    ${step >= num 
                      ? 'bg-[#3ECF8E] text-white shadow-lg' 
                      : 'bg-white border-2 border-gray-200 text-gray-400'
                    }
                  `}
                >
                  {num}
                </div>
              ))}
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8">
          <div className="transition-all duration-300 transform">
            {renderStep()}
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}

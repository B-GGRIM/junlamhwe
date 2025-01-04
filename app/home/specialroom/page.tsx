"use client"

import Header from "@/app/components/Header/Header";
import { useState } from "react";
import TimeSelection from "@/app/components/TimeSelection/TimeSelection";
import LocationSelection from "@/app/components/LocationSelection/LocationSelection";
import PurposeSelection from "@/app/components/PurposeSelection/PurposeSelection";
import StudentSelection from "@/app/components/StudentSelection/StudentSelection";
import TeacherSelection from "@/app/components/TeacherSelection/TeacherSelection";
import Footer from "@/app/components/Footer/Footer";

export default function SpecialRoom() {
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

  const handleSubmit = () => {
    // 여기에 제출 로직 구현
    console.log('최종 제출된 데이터:', formData);
  };

  return (
    <div className="min-h-screen bg-white">
      <Header />
      <div className="max-w-2xl mx-auto p-6 mt-8 mb-10">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-3">특별실 신청</h1>
          <div className="relative mb-8">
            <div className="absolute top-1/2 left-0 right-0 h-1 bg-gray-100 -translate-y-1/2" />
            <div 
              className="absolute top-1/2 left-0 h-1 bg-blue-500 transition-all duration-300 -translate-y-1/2"
              style={{ width: `${(step / 5) * 100}%` }}
            />
            <div className="relative flex justify-between">
              {[1, 2, 3, 4, 5].map((num) => (
                <div
                  key={num}
                  className={`
                    w-8 h-8 rounded-full flex items-center justify-center text-sm
                    transition-all duration-300 relative
                    ${step >= num 
                      ? 'bg-blue-500 text-white shadow-lg' 
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

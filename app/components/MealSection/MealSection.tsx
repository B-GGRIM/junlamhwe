'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { getMeals } from '@/lib/neis'
import Neis from "@my-school.info/neis-api";

// 타입 정의 추가
interface MealInfo {
  MMEAL_SC_NM: string;
  DDISH_NM: string;
}

interface SchoolInfo {
  ATPT_OFCDC_SC_CODE: string;
  SD_SCHUL_CODE: string;
}

export default function MealSection() {
  const [meals, setMeals] = useState<MealInfo[]>([])
  const [error, setError] = useState<string>('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchMeals() {
      try {
        if (!process.env.NEXT_PUBLIC_NEIS_API_KEY) {
          throw new Error('NEIS API 키가 설정되지 않았습니다.');
        }

        const neis = new Neis({
          key: process.env.NEXT_PUBLIC_NEIS_API_KEY
        });
        
        // 제주과학고등학교 정보 직접 지정
        const schoolInfo = await neis.getSchoolInfo({ 
          SCHUL_NM: "제주과학고등학교"
        }).catch(() => null);
        
        if (!schoolInfo || !Array.isArray(schoolInfo) || schoolInfo.length === 0) {
          throw new Error('학교 정보를 찾을 수 없습니다.');
        }

        // 오늘 날짜 형식 변환
        const today = new Date().toISOString().split('T')[0].replace(/-/g, '');
        
        // 급식 정보 조회
        const mealInfo = await neis.getMealInfo({ 
          ATPT_OFCDC_SC_CODE: schoolInfo[0].ATPT_OFCDC_SC_CODE,
          SD_SCHUL_CODE: schoolInfo[0].SD_SCHUL_CODE,
          MLSV_YMD: today
        }).catch(() => null);
          
        if (!mealInfo) {
          setMeals([]);
          return;
        }

        if (Array.isArray(mealInfo)) {
          setMeals(mealInfo);
        } else {
          setMeals([]);
        }
      } catch (error) {
        console.error('급식 정보 로딩 실패:', error);
        setError(error instanceof Error ? error.message : '급식 정보를 불러오는데 실패했습니다.');
      } finally {
        setLoading(false);
      }
    }
    
    fetchMeals();
  }, []);

  const formatMeal = (dishName: string) => {
    return dishName
      .replace(/<br\/>/g, '\n')
      .replace(/\([0-9.]+\)/g, '')
      .split('\n')
  }

  if (error) {
    return (
      <div className="w-full max-w-7xl mx-auto mt-12 px-6">
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="w-full max-w-7xl mx-auto mt-12 px-6">
        <div className="animate-pulse bg-gray-200 rounded-lg h-64"></div>
      </div>
    )
  }

  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.6 }}
      className="w-full max-w-7xl mx-auto mt-12 px-6"
    >
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {['조식', '중식', '석식'].map((mealType) => {
          const meal = meals.find(m => m.MMEAL_SC_NM === mealType)
          
          return (
            <motion.div
              key={mealType}
              whileHover={{ scale: 1.02 }}
              className="bg-white rounded-xl shadow-lg p-6 min-h-[200px]"
            >
              <h3 className="text-lg font-semibold mb-4 text-gray-700">
                {mealType}
              </h3>
              
              {meal ? (
                <ul className="space-y-2">
                  {formatMeal(meal.DDISH_NM).map((dish, index) => (
                    <li 
                      key={index}
                      className="text-gray-600"
                    >
                      {dish.trim()}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-gray-500 italic">
                  급식 정보가 없습니다
                </p>
              )}
            </motion.div>
          )
        })}
      </div>
    </motion.section>
  )
}
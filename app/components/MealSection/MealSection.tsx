'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { getMeals } from '@/lib/neis'

export default function MealSection() {
  const [meals, setMeals] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchMeals() {
      try {
        const mealsData = await getMeals('')
        setMeals(mealsData || [])
      } catch (error) {
        console.error('급식 정보 로딩 실패:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchMeals()
  }, [])

  const formatMeal = (dishName: string) => {
    return dishName
      .replace(/<br\/>/g, '\n')
      .replace(/\([0-9.]+\)/g, '')
      .split('\n')
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
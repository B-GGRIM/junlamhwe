interface MealInfo {
  DDISH_NM: string; // 식단 내용
  MLSV_YMD: string; // 급식일자
  MMEAL_SC_NM: string; // 식사명(조식/중식/석식)
}

async function getSchoolInfo(schoolName: string) {
  const url = `https://open.neis.go.kr/hub/schoolInfo` +
    `?KEY=${process.env.NEXT_PUBLIC_NEIS_API_KEY}` +
    `&Type=json` +
    `&ATPT_OFCDC_SC_CODE=J10` +
    `&SCHUL_NM=${encodeURIComponent(schoolName)}`

  const response = await fetch(url)
  const data = await response.json()
  
  if (data.schoolInfo) {
    return data.schoolInfo[1].row[0]
  }
  return null
}

export async function getMeals(schoolCode: string) {
  try {
    // 한국 시간 기준으로 날짜 설정
    const now = new Date()
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000)
    const kstGap = 9 * 60 * 60000
    const today = new Date(utc + kstGap)
    
    const dateString = today.getFullYear() +
      String(today.getMonth() + 1).padStart(2, '0') +
      String(today.getDate()).padStart(2, '0')

    // API 요청 URL 구성
    const url = 'https://open.neis.go.kr/hub/mealServiceDietInfo'
    const params = new URLSearchParams({
      KEY: process.env.NEXT_PUBLIC_NEIS_API_KEY || '',
      Type: 'json',
      ATPT_OFCDC_SC_CODE: 'J10',
      SD_SCHUL_CODE: '9290066',  // 제주과학고등학교 코드
      MLSV_YMD: dateString
    })

    console.log('급식 조회 날짜:', dateString)

    const response = await fetch(`${url}?${params}`)
    const data = await response.json()

    console.log('API 응답:', data)

    // 급식 정보가 있는 경우
    if (data.mealServiceDietInfo?.[1]?.row) {
      return data.mealServiceDietInfo[1].row
    }

    // 급식 정보가 없는 경우
    console.log('급식 정보가 없습니다:', data.RESULT?.MESSAGE || '알 수 없는 이유')
    return []

  } catch (error) {
    console.error('급식 정보 조회 중 오류 발생:', error)
    return []
  }
}
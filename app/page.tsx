'use client'

import { useState, useEffect } from 'react';
import PreHeader from './components/PreHeader/PreHeader';
import { createClientComponentClient } from '@supabase/auth-helpers-nextjs'
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import MealSection from './components/MealSection/MealSection';
import Footer from './components/Footer/Footer';

// 인터페이스 정의 추가
interface FormErrors {
  login?: string;
  name?: string;
  studentId?: string;
  username?: string;
  password?: string;
  confirmPassword?: string;
  signup?: string;
}

export default function Home() {
  const [showLoginPopup, setShowLoginPopup] = useState(false)
  const [isLoginForm, setIsLoginForm] = useState(true)
  const [loading, setLoading] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [signupStep, setSignupStep] = useState(1)
  const [name, setName] = useState('')
  const [studentId, setStudentId] = useState('')
  const [username, setUsername] = useState('')
  const [formErrors, setFormErrors] = useState<FormErrors>({
    login: '',
    name: '',
    studentId: '',
    username: '',
    password: '',
    confirmPassword: '',
    signup: ''
  })
  const router = useRouter()
  const [isPasswordTouched, setIsPasswordTouched] = useState(false)
  const [isConfirmPasswordTouched, setIsConfirmPasswordTouched] = useState(false)
  const [signupSuccess, setSignupSuccess] = useState(false)
  const [isLoading, setIsLoading] = useState(true);

  const supabase = createClientComponentClient()

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 200);

    return () => clearTimeout(timer);
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    
    if (!username || !password) {
      setFormErrors(prev => ({
        ...prev,
        login: '아이디와 비밀번호를 입력해주세요.'
      }))
      return
    }

    try {
      const { data: allowedUser, error } = await supabase
        .from('allowed_users')
        .select('*')
        .eq('username', username)
        .eq('password', password)
        .single()

      if (error || !allowedUser) {
        setFormErrors(prev => ({
          ...prev,
          login: '로그인이 허용되지 않은 사용자입니다.'
        }))
        return
      }

      document.cookie = 'isLoggedIn=true; path=/'
      sessionStorage.setItem('isLoggedIn', 'true')
      sessionStorage.setItem('userData', JSON.stringify({
        name: allowedUser.name,
        username: allowedUser.username
      }))

      console.log('=== 로그인 성공 ===')
      console.log('허용된 사용자:', {
        name: allowedUser.name,
        username: allowedUser.username
      })
      console.log('==================')

      router.push('/home')
      
    } catch (error: any) {
      console.error('로그인 에러:', error)
      setFormErrors(prev => ({
        ...prev,
        login: '로그인에 실패했습니다.'
      }))
    } finally {
      setLoading(false)
    }
  }

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault()
    console.log('회원가입 시도 중...')
    
    if (!name || !studentId || !username || !password) {
      setFormErrors(prev => ({
        ...prev,
        signup: '모든 필드를 입력해주세요.'
      }))
      return
    }

    try {
      setLoading(true)
      
      console.log('입력된 데이터:', {
        name,
        student_id: studentId,
        username,
        password
      })

      const { error } = await supabase
        .from('profiles')
        .insert({
          name,
          student_id: studentId,
          username,
          password
        })

      if (error) {
        console.error('Supabase 에러:', error)
        throw error
      }

      console.log('=== 회원가입 완료 ===')
      console.log('이름:', name)
      console.log('학번:', studentId)
      console.log('아이디:', username)
      console.log('비밀번호:', password)
      console.log('==================')

      setSignupSuccess(true)
      setSignupStep(5)
      
    } catch (error: any) {
      console.error('회원가입 에러:', error.message)
      setFormErrors(prev => ({
        ...prev,
        signup: '회원가입 중 오류가 발생했습니다.'
      }))
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setEmail('')
    setPassword('')
    setConfirmPassword('')
    setName('')
    setStudentId('')
    setUsername('')
    setSignupStep(1)
    setSignupSuccess(false)
  }

  const toggleForm = () => {
    setIsLoginForm(!isLoginForm)
    resetForm()
  }

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value
    setPassword(newPassword)
    if (isPasswordTouched) {
      const errors = { ...formErrors }
      errors.password = newPassword.trim() ? '' : '비밀번호를 입력해주세요'
      if (isConfirmPasswordTouched && confirmPassword) {
        errors.confirmPassword = newPassword === confirmPassword ? '' : '비밀번호가 일치하지 않습니다'
      }
      setFormErrors(prev => ({ ...prev, ...errors }))
    }
  }

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newConfirmPassword = e.target.value
    setConfirmPassword(newConfirmPassword)
    if (isConfirmPasswordTouched) {
      const errors = { ...formErrors }
      errors.confirmPassword = newConfirmPassword.trim() 
        ? (newConfirmPassword === password ? '' : '비밀번호가 일치하지 않습니다')
        : '비밀번호를 입력해주세요'
      setFormErrors(prev => ({ ...prev, ...errors }))
    }
  }

  const handlePasswordBlur = () => {
    setIsPasswordTouched(true)
    const errors = { ...formErrors }
    errors.password = password.trim() ? '' : '비밀번호를 입력해주세요'
    setFormErrors(prev => ({ ...prev, ...errors }))
  }

  const handleConfirmPasswordBlur = () => {
    setIsConfirmPasswordTouched(true)
    const errors = { ...formErrors }
    errors.confirmPassword = confirmPassword.trim()
      ? (confirmPassword === password ? '' : '비밀번호가 일치하지 않습니다')
      : '비밀번호를 입력해주세요'
    setFormErrors(prev => ({ ...prev, ...errors }))
  }

  const handleNextStep = () => {
    setFormErrors({ name: '', studentId: '', username: '', password: '', confirmPassword: '' })
    setIsPasswordTouched(false)
    setIsConfirmPasswordTouched(false)
    
    switch (signupStep) {
      case 1:
        if (!name.trim()) {
          setFormErrors(prev => ({ ...prev, name: '이름을 입력해주세요' }))
          return
        }
        break
      case 2:
        if (!studentId.trim()) {
          setFormErrors(prev => ({ ...prev, studentId: '학번을 입력해주세요' }))
          return
        }
        if (!/^\d{4}$/.test(studentId)) {
          setFormErrors(prev => ({ ...prev, studentId: '올바른 학번 4자리를 입력해주세요' }))
          return
        }
        break
      case 3:
        if (!username.trim()) {
          setFormErrors(prev => ({ ...prev, username: '아이디를 입력해주세요' }))
          return
        }
        break
    }
    setSignupStep(prev => prev + 1)
  }

  const handlePrevStep = () => {
    setSignupStep(prev => prev - 1)
  }

  const handleKeyPress = (e: React.KeyboardEvent, action: () => void) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      action();
    }
  }

  const handleSignupKeyPress = (e: React.KeyboardEvent) => {
    if (signupStep < 4) {
      handleKeyPress(e, handleNextStep);
    } else {
      handleKeyPress(e, () => handleSignup(e as any));
    }
  }

  const isSignupButtonEnabled = () => {
    if (signupStep === 4) {
      return password && 
             confirmPassword && 
             password === confirmPassword && 
             !formErrors.password && 
             !formErrors.confirmPassword;
    }
    return true;
  };

  const renderSignupStep = () => {
    switch (signupStep) {
      case 1:
        return (
          <div className="space-y-6">
            <div>
              <label className="text-sm font-medium text-gray-700 mb-1 block">이름</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyPress={(e) => handleSignupKeyPress(e)}
                className={`w-full p-3 border ${formErrors.name ? 'border-red-500' : 'border-gray-300'} rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200`}
                placeholder="이름을 입력하세요"
              />
              {formErrors.name && (
                <p className="mt-1 text-sm text-red-500">{formErrors.name}</p>
              )}
            </div>
            <button
              type="button"
              onClick={handleNextStep}
              className="w-full bg-[#3ECF8E] text-white p-3 rounded-xl font-semibold hover:bg-[#3ECF8E] transition-all duration-200 transform hover:scale-[1.02]"
            >
              다음으로
            </button>
          </div>
        )

      case 2:
        return (
          <div className="space-y-6">
            <div>
              <label className="text-sm font-medium text-gray-700 mb-1 block">학번</label>
              <input
                type="text"
                value={studentId}
                onChange={(e) => setStudentId(e.target.value.replace(/\D/g, '').slice(0, 5))}
                onKeyPress={(e) => handleSignupKeyPress(e)}
                className={`w-full p-3 border ${formErrors.studentId ? 'border-red-500' : 'border-gray-300'} rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200`}
                placeholder="학번 4자리를 입력하세요"
                maxLength={4}
              />
              {formErrors.studentId && (
                <p className="mt-1 text-sm text-red-500">{formErrors.studentId}</p>
              )}
            </div>
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={handlePrevStep}
                className="w-full bg-gray-200 text-gray-800 p-3 rounded-xl font-semibold hover:bg-gray-300 transition-all duration-200"
              >
                이전으로
              </button>
              <button
                type="button"
                onClick={handleNextStep}
                className="w-full bg-[#3ECF8E] text-white p-3 rounded-xl font-semibold hover:bg-[#3ECF8E] transition-all duration-200 transform hover:scale-[1.02]"
              >
                다음으로
              </button>
            </div>
          </div>
        )

      case 3:
        return (
          <div className="space-y-6">
            <div>
              <label className="text-sm font-medium text-gray-700 mb-1 block">아이디</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyPress={(e) => handleSignupKeyPress(e)}
                className={`w-full p-3 border ${formErrors.username ? 'border-red-500' : 'border-gray-300'} rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200`}
                placeholder="아이디를 입력하세요"
              />
              {formErrors.username && (
                <p className="mt-1 text-sm text-red-500">{formErrors.username}</p>
              )}
            </div>
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={handlePrevStep}
                className="w-full bg-gray-200 text-gray-800 p-3 rounded-xl font-semibold hover:bg-gray-300 transition-all duration-200"
              >
                이전으로
              </button>
              <button
                type="button"
                onClick={handleNextStep}
                className="w-full bg-[#3ECF8E] text-white p-3 rounded-xl font-semibold hover:bg-[#3ECF8E] transition-all duration-200 transform hover:scale-[1.02]"
              >
                다음으로
              </button>
            </div>
          </div>
        )

      case 4:
        return (
          <div className="space-y-6">
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-gray-700 mb-1 block">비밀번호</label>
                <input
                  type="password"
                  value={password}
                  onChange={handlePasswordChange}
                  onBlur={handlePasswordBlur}
                  onKeyPress={(e) => handleSignupKeyPress(e)}
                  className={`w-full p-3 border ${isPasswordTouched && formErrors.password ? 'border-red-500' : 'border-gray-300'} rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200`}
                  placeholder="비밀번호를 입력하세요"
                />
                {isPasswordTouched && formErrors.password && (
                  <p className="mt-1 text-sm text-red-500">{formErrors.password}</p>
                )}
              </div>
              <div>
                <label className="text-sm font-medium text-gray-700 mb-1 block">비밀번호 확인</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={handleConfirmPasswordChange}
                  onBlur={handleConfirmPasswordBlur}
                  onKeyPress={(e) => handleSignupKeyPress(e)}
                  className={`w-full p-3 border ${isConfirmPasswordTouched && formErrors.confirmPassword ? 'border-red-500' : 'border-gray-300'} rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200`}
                  placeholder="비밀번호를 다시 입력하세요"
                />
                {isConfirmPasswordTouched && formErrors.confirmPassword && (
                  <p className="mt-1 text-sm text-red-500">{formErrors.confirmPassword}</p>
                )}
              </div>
            </div>
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={handlePrevStep}
                className="w-full bg-gray-200 text-gray-800 p-3 rounded-xl font-semibold hover:bg-gray-300 transition-all duration-200"
              >
                이전으로
              </button>
              <button
                type="submit"
                disabled={loading || !isSignupButtonEnabled()}
                className={`w-full p-3 rounded-xl font-semibold transition-all duration-200 transform border-2 ${
                  loading 
                    ? 'bg-gray-400 text-white cursor-not-allowed hover:bg-gray-400'
                    : 'bg-[#006239] text-white border-[#128453] hover:bg-[#006239] hover:scale-[1.02]'
                }`}
              >
                {loading ? '가입 중...' : '회원가입'}
              </button>
            </div>
          </div>
        )

      case 5:
        return (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center space-y-6"
          >
            <div className="flex flex-col items-center space-y-4">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center">
                <svg 
                  className="w-8 h-8 text-green-500" 
                  fill="none" 
                  stroke="currentColor" 
                  viewBox="0 0 24 24"
                >
                  <path 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    strokeWidth={2} 
                    d="M5 13l4 4L19 7" 
                  />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-900">
                회원가입이 완료되었습니다!
              </h3>
              <p className="text-gray-600">
                Bunker 관리자의 승인 후 이용 가능합니다.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setIsLoginForm(true)
                resetForm()
              }}
              className="w-full bg-[#3ECF8E] text-white p-3 rounded-xl font-semibold hover:bg-[#3ECF8E] transition-all duration-200 transform hover:scale-[1.02]"
            >
              로그인하기
            </button>
          </motion.div>
        )

      default:
        return null
    }
  }

  const openLoginPopup = () => {
    setIsLoginForm(true)
    resetForm()
    setShowLoginPopup(true)
  }

  const renderLoginForm = () => (
    <form onSubmit={handleLogin} className="space-y-5">
      <div className="space-y-4">
        <div>
          <label className="text-sm font-medium text-gray-700 mb-1 block">아이디</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyPress={(e) => handleKeyPress(e, () => handleLogin(e as any))}
            className="w-full p-3 border border-gray-300 rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200"
            placeholder="아이디를 입력하세요"
          />
        </div>
        <div>
          <label className="text-sm font-medium text-gray-700 mb-1 block">비밀번호</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyPress={(e) => handleKeyPress(e, () => handleLogin(e as any))}
            className="w-full p-3 border border-gray-300 rounded-xl bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all duration-200"
            placeholder="비밀번호를 입력하세요"
          />
        </div>
      </div>

      {formErrors.login && (
        <p className="text-red-500 text-sm">{formErrors.login}</p>
      )}

      <button 
        type="submit" 
        disabled={loading}
        className={`w-full p-3 rounded-xl font-semibold transition-all duration-200 transform border-2 ${
          loading 
            ? 'bg-gray-400 text-white cursor-not-allowed hover:bg-gray-400'
            : 'bg-[#00c573] text-white hover:bg-[#006239] hover:scale-[1.00]'
        }`}
      >
        로그인
      </button>
    </form>
  )

  return (
    <>
      <div className={`min-h-screen flex flex-col relative ${showLoginPopup ? 'brightness-75' : ''}`}>
        <PreHeader />
        <main className="flex-1">
          {/* Hero Section */}
          <div className="relative w-full h-[75vh] bg-cover bg-center" style={{ backgroundImage: 'url("/background01.jpg")' }}>
            {/* Noise overlay */}
            <div 
              className="absolute inset-0 opacity-[0.25] mix-blend-soft-light"
              style={{
                backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")`,
                backgroundSize: '200px 200px'
              }}
            ></div>

            {/* Overlay for depth */}
            <div className="absolute inset-0 bg-gradient-to-br from-transparent via-black/10 to-black/20"></div>
            
            {/* Content */}
            <div className="relative h-full flex items-center max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex flex-col items-start w-full ">
                {/* Text Content and Button in one group */}
                <div className="flex items-center gap-8">
                  <div className="text-left">
                    <h2 className="text-lg font-medium text-gray-300 mb-3"></h2>
                    <h1 className="text-4xl text-white mb-4 leading-tight">
                      <span className="font-medium">새로워진</span>{' '}
                      <span className="font-extrabold">이디저디</span>
                    </h1>
                    <p className="text-base text-gray-300">
                      새로운 이디저디를 지금 바로 만나보세요
                    </p>
                  </div>

                  <button
                    className="font-bold px-6 py-3 bg-white text-black rounded-lg hover:bg-gray-200 transition-colors ml-3"
                    onClick={openLoginPopup}
                  >
                    시작하기
                  </button>
                </div>
              </div>

              {/* Pagination Dots */}
              <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 flex space-x-2">

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
        </main>
      </div>

      <AnimatePresence>
        {showLoginPopup && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0 }}
            className="fixed inset-0 bg-black/30 flex items-center justify-center p-4 z-50"
            onClick={(e) => {
              if (e.target === e.currentTarget) setShowLoginPopup(false)
            }}
          >
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0 }}
              className="bg-white rounded-2xl shadow-2xl w-full max-w-md relative overflow-hidden"
              onClick={e => e.stopPropagation()}
            >
              <button
                onClick={() => setShowLoginPopup(false)}
                className="absolute top-6 right-6 text-gray-400 hover:text-gray-600 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>

              <div className="p-8">
                <h2 className="text-3xl font-bold mb-2 text-center text-gray-800">
                  {isLoginForm ? '로그인' : '회원가입'}
                </h2>
                <p className="text-center text-gray-600 mb-8">
                  {isLoginForm || signupStep === 5
                    ? '' 
                    : `${signupStep}/4 단계`}
                </p>
                
                {isLoginForm ? (
                  renderLoginForm()
                ) : (
                  <form onSubmit={handleSignup}>
                    {renderSignupStep()}
                  </form>
                )}

                {(isLoginForm || (!isLoginForm && signupStep < 4)) && (
                  <p className="text-center text-gray-600 text-sm mt-6">
                    {isLoginForm ? '아직 계정이 없으신가요?' : '이미 계정이 있으신가요?'}{' '}
                    <button 
                      type="button"
                      onClick={toggleForm}
                      className="text-[#3ECF8E] hover:text-[#3ECF8E] font-medium"
                    >
                      {isLoginForm ? '회원가입' : '로그인'}
                    </button>
                  </p>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
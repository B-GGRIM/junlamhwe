import { Fragment } from 'react';
import { Listbox, Transition } from '@headlessui/react';
import { ChevronDownIcon } from '@heroicons/react/20/solid';

interface PurposeSelectionProps {
  formData: {
    purpose: string;
    purposeDetail?: string;
  };
  setFormData: (data: any) => void;
  onNext: () => void;
  onBack: () => void;
}

export default function PurposeSelection({
  formData,
  setFormData,
  onNext,
  onBack
}: PurposeSelectionProps) {
  const purposes = [
    "R&E",
    "과제 연구",
    "개인 연구",
    "연구 활동",
    "브릿지 수업",
    "심층 면접",
    "자기소개서 작성",
    "자연탐사",
    "무한상상 STEAM",
    "그룹 스터디",
    "기타"
  ];

  return (
    <div className="bg-white p-6">
      <div className="mb-8">
        <h2 className="text-2xl font-bold mb-2">사용 목적</h2>
        <p className="text-gray-500 mb-6 text-sm">특별실 사용 목적을 선택해주세요</p>
      </div>

      <Listbox 
        value={formData.purpose} 
        onChange={(value) => {
          setFormData({ 
            ...formData, 
            purpose: value,
            purposeDetail: value === "기타" ? formData.purposeDetail : undefined 
          })
        }}
      >
        <div className="relative mt-1">
          <Listbox.Button className="relative w-full cursor-default rounded-lg bg-white py-4 pl-4 pr-10 text-left border border-gray-200 focus:outline-none focus-visible:border-blue-500 focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-opacity-75 focus-visible:ring-offset-2 focus-visible:ring-offset-blue-300">
            <span className="block truncate text-[17px]">
              {formData.purpose || '사용 목적을 선택해주세요'}
            </span>
            <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronDownIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
            </span>
          </Listbox.Button>
          <Transition
            as={Fragment}
            leave="transition ease-in duration-100"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <Listbox.Options className="absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
              {purposes.map((purpose) => (
                <Listbox.Option
                  key={purpose}
                  value={purpose}
                  className={({ active, selected }) =>
                    `relative cursor-default select-none py-3 pl-4 pr-4 text-[17px] ${
                      active ? 'bg-blue-100 text-blue-900' : 'text-gray-900'
                    } ${selected ? 'bg-blue-50' : ''}`
                  }
                >
                  {purpose}
                </Listbox.Option>
              ))}
            </Listbox.Options>
          </Transition>
        </div>
      </Listbox>

      {formData.purpose === "기타" && (
        <div className="mt-4">
          <label htmlFor="purposeDetail" className="block text-[15px] font-medium text-gray-700 mb-2">
            사용 목적을 입력해주세요
          </label>
          <input
            type="text"
            id="purposeDetail"
            value={formData.purposeDetail || ''}
            onChange={(e) => setFormData({ ...formData, purposeDetail: e.target.value })}
            className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 text-[17px]"
            placeholder="구체적인 사용 목적을 입력해주세요"
          />
        </div>
      )}

      <div className="flex gap-3 mt-8">
        <button
          onClick={onBack}
          className="w-full py-3.5 px-4 rounded-xl border border-gray-200 text-[17px] text-gray-700 font-medium hover:bg-gray-50 transition-colors"
        >
          이전으로
        </button>
        <button
          onClick={onNext}
          disabled={!formData.purpose || (formData.purpose === "기타" && !formData.purposeDetail)}
          className="w-full py-3.5 px-4 rounded-xl bg-blue-500 text-[17px] text-white font-medium hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          다음으로
        </button>
      </div>
    </div>
  );
}